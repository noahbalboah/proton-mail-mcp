//! Append-only audit log of every write, one JSON object per line, plus the rolling 24-hour budget
//! for moves, trash and label removal. Fail closed: if the intent line cannot be written, the
//! write does not run.
//!
//! Each write produces two lines with the same `id`: `"phase":"intent"` before anything is sent to
//! Bridge, then `"phase":"done"` or `"phase":"failed"`. The budget is rebuilt from intent lines on
//! startup, so a restart does not reset it.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::json::{self, Json};

const DAY_SECS: u64 = 86_400;

pub struct AuditLog {
    file: Mutex<File>,
    /// (unix seconds, cost) of recent budgeted writes.
    spent: Mutex<VecDeque<(u64, u32)>>,
    budget: u32,
}

pub fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl AuditLog {
    pub fn open(path: &Path, budget: u32) -> std::io::Result<Self> {
        let mut spent = VecDeque::new();
        if let Ok(f) = File::open(path) {
            let cutoff = now_unix().saturating_sub(DAY_SECS);
            for line in BufReader::new(f).lines().map_while(Result::ok) {
                if let Some((ts, cost)) = intent_cost(&line)
                    && ts > cutoff
                    && cost > 0
                {
                    spent.push_back((ts, cost));
                }
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { file: Mutex::new(file), spent: Mutex::new(spent), budget })
    }

    /// Messages still allowed in the current 24-hour window.
    pub fn remaining(&self, now: u64) -> u32 {
        let mut spent = self.spent.lock().unwrap_or_else(|p| p.into_inner());
        while spent.front().is_some_and(|(ts, _)| *ts + DAY_SECS <= now) {
            spent.pop_front();
        }
        self.budget.saturating_sub(spent.iter().map(|(_, c)| *c).sum())
    }

    /// Charge `cost` against the budget and write the intent line. Errors mean: do not run.
    pub fn begin(&self, id: &str, tool: &str, args: Json, cost: u32) -> Result<(), String> {
        let now = now_unix();
        if cost > 0 {
            let left = self.remaining(now);
            if cost > left {
                return Err(format!(
                    "Daily limit reached: moves, trash and label removals may touch at most {} messages \
                     in 24 hours, and {left} remain. Ask the user to do larger clean-ups in Proton Mail.",
                    self.budget
                ));
            }
        }
        self.write(Json::obj([
            ("ts", Json::Number(now.to_string())),
            ("id", Json::str(id)),
            ("phase", Json::str("intent")),
            ("tool", Json::str(tool)),
            ("cost", Json::Number(cost.to_string())),
            ("args", args),
        ]))
        .map_err(|_| "The audit log could not be written, so no change was made.".to_string())?;
        if cost > 0 {
            self.spent.lock().unwrap_or_else(|p| p.into_inner()).push_back((now, cost));
        }
        Ok(())
    }

    /// Record the result. A failure to write here is reported on stderr only: the change is done.
    pub fn finish(&self, id: &str, tool: &str, result: Result<&Json, &str>) {
        let mut fields = vec![
            ("ts".to_string(), Json::Number(now_unix().to_string())),
            ("id".to_string(), Json::str(id)),
            ("tool".to_string(), Json::str(tool)),
        ];
        match result {
            Ok(detail) => {
                fields.push(("phase".into(), Json::str("done")));
                fields.push(("detail".into(), detail.clone()));
            }
            Err(e) => {
                fields.push(("phase".into(), Json::str("failed")));
                fields.push(("error".into(), Json::str(e)));
            }
        }
        if self.write(Json::Object(fields)).is_err() {
            eprintln!("audit: could not write result line for {id}");
        }
    }

    fn write(&self, entry: Json) -> std::io::Result<()> {
        let line = entry.to_string();
        eprintln!("audit {line}");
        let mut f = self.file.lock().unwrap_or_else(|p| p.into_inner());
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
        f.flush()
    }
}

fn intent_cost(line: &str) -> Option<(u64, u32)> {
    let j = json::parse(line.as_bytes()).ok()?;
    if j.get("phase").and_then(Json::as_str) != Some("intent") {
        return None;
    }
    let ts = j.get("ts").and_then(Json::as_u64)?;
    let cost = j.get("cost").and_then(Json::as_u64).and_then(|c| u32::try_from(c).ok())?;
    Some((ts, cost))
}

/// RFC 5322 date in UTC, e.g. "Wed, 25 Nov 2026 21:48:03 +0000".
pub fn rfc5322_date(unix: u64) -> String {
    let days = (unix / DAY_SECS) as i64;
    let secs = unix % DAY_SECS;
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} +0000",
        WEEKDAYS[days.rem_euclid(7) as usize],
        day,
        MONTHS[(month - 1) as usize],
        year,
        secs / 3_600,
        (secs % 3_600) / 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(rfc5322_date(0), "Thu, 01 Jan 1970 00:00:00 +0000");
        assert_eq!(rfc5322_date(951_782_400), "Tue, 29 Feb 2000 00:00:00 +0000");
        assert_eq!(rfc5322_date(1_795_662_504), "Thu, 26 Nov 2026 03:08:24 +0000");
    }

    fn temp_path(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("pmm-audit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn budget_is_enforced_and_survives_reopen() {
        let p = temp_path("budget");
        {
            let log = AuditLog::open(&p, 10).unwrap();
            log.begin("a", "trash_messages", Json::Null, 6).unwrap();
            log.finish("a", "trash_messages", Ok(&Json::Null));
            assert!(log.begin("b", "trash_messages", Json::Null, 5).is_err());
            log.begin("c", "mark_messages", Json::Null, 0).unwrap();
        }
        let log = AuditLog::open(&p, 10).unwrap();
        assert_eq!(log.remaining(now_unix()), 4);
        assert!(log.begin("d", "move_messages", Json::Null, 4).is_ok());
        assert_eq!(log.remaining(now_unix()), 0);
        assert_eq!(log.remaining(now_unix() + DAY_SECS + 1), 10);
        let text = std::fs::read_to_string(&p).unwrap();
        assert_eq!(text.lines().count(), 4); // the refused call writes nothing
        assert!(text.contains("\"phase\":\"done\""));
        let _ = std::fs::remove_file(&p);
    }
}
