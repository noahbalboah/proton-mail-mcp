//! Append-only audit log of every write, one JSON object per line. Fail closed: if the intent line
//! cannot be written, the write does not run.
//!
//! Each write produces two lines with the same `id`: `"phase":"intent"` before anything is sent to
//! Bridge, then `"phase":"done"` or `"phase":"failed"`.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::json::Json;

const DAY_SECS: u64 = 86_400;

pub struct AuditLog {
    file: Mutex<File>,
}

pub fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl AuditLog {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { file: Mutex::new(file) })
    }

    /// Write the intent line. An error means: do not run the change.
    pub fn begin(&self, id: &str, tool: &str, args: Json) -> Result<(), String> {
        self.write(Json::obj([
            ("ts", Json::Number(now_unix().to_string())),
            ("id", Json::str(id)),
            ("phase", Json::str("intent")),
            ("tool", Json::str(tool)),
            ("args", args),
        ]))
        .map_err(|_| "The audit log could not be written, so no change was made.".to_string())
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
    fn writes_intent_and_result_lines() {
        let p = temp_path("log");
        {
            let log = AuditLog::open(&p).unwrap();
            log.begin("a", "trash_messages", Json::Null).unwrap();
            log.finish("a", "trash_messages", Ok(&Json::Null));
            log.begin("b", "move_messages", Json::Null).unwrap();
            log.finish("b", "move_messages", Err("refused"));
        }
        // Reopening appends; it never truncates.
        AuditLog::open(&p).unwrap().begin("c", "mark_messages", Json::Null).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert_eq!(text.lines().count(), 5);
        assert!(text.contains("\"phase\":\"done\""));
        assert!(text.contains("\"phase\":\"failed\""));
        let _ = std::fs::remove_file(&p);
    }
}
