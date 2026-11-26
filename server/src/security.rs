//! Sender and phishing checks from headers and extracted HTML links (no network I/O).

#![allow(clippy::too_many_lines)]

use std::fmt::Write as _;

const MAX_HEADER_SCAN: usize = 256 * 1024;
const MAX_LINE: usize = 16 * 1024;
const MAX_REASONS: usize = 32;
const MAX_EDIT_LABEL: usize = 64;

/// Advice level for the agent; nothing is blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Pass,
    Caution,
    Danger,
    Unverified,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Caution => "CAUTION",
            Self::Danger => "DANGER",
            Self::Unverified => "UNVERIFIED",
        }
    }
}

/// Result of [`check`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub level: Level,
    pub summary: String,
    pub reasons: Vec<String>,
}

/// Visible text and destination from an HTML anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub text: String,
    pub href: String,
}

/// Analyze `raw_headers` (CRLF, folded) and optional `links` from the HTML body.
pub fn check(raw_headers: &[u8], links: &[Link]) -> Verdict {
    let raw = if raw_headers.len() > MAX_HEADER_SCAN {
        &raw_headers[..MAX_HEADER_SCAN]
    } else {
        raw_headers
    };
    let lines = unfold_headers(raw);
    let mut reasons = Vec::new();
    let trusted_auth = parse_trusted_auth(&lines);
    let forged_auth = proton_auth_inconsistent(&lines);
    if forged_auth {
        push_reason(&mut reasons, "message carries forged authentication headers");
    }

    let pm = parse_proton_appended(&lines);
    if pm.forged_pm_headers {
        push_reason(&mut reasons, "message carries forged Proton headers");
    }

    if let Some(ref action) = pm.spam_action {
        match action.as_str() {
            "phishing" => push_reason(&mut reasons, "Proton flagged phishing"),
            "spam" => push_reason(&mut reasons, "Proton marked as spam"),
            _ => {}
        }
    }

    let from = parse_from_reply(&lines, b"from");
    let reply_to = parse_from_reply(&lines, b"reply-to");

    if let Some(f) = &from {
        if domain_is_punycode(&f.domain) {
            push_reason(&mut reasons, "From domain uses punycode");
        }
        if domain_mixed_script(&f.domain) {
            push_reason(&mut reasons, "From domain mixes scripts");
        }
        if display_name_domain_mismatch(f) {
            push_reason(
                &mut reasons,
                &format!("display name suggests a different sender than {}", f.domain),
            );
        }
        if display_name_lookalike(f) {
            push_reason(
                &mut reasons,
                &format!(
                    "display name resembles the From domain label but differs ({})",
                    f.domain
                ),
            );
        }
    }

    if let (Some(f), Some(r)) = (&from, &reply_to) {
        let fo = org_domain(&f.domain);
        let ro = org_domain(&r.domain);
        if !fo.is_empty() && !ro.is_empty() && fo != ro {
            push_reason(
                &mut reasons,
                &format!("Reply-To goes to a different domain ({})", r.domain),
            );
        }
    }

    let from_domain = from.as_ref().map(|f| f.domain.as_str()).unwrap_or("");
    let from_org = org_domain(from_domain);

    if let Some(auth) = &trusted_auth {
        if auth.dmarc_fail {
            let dom = auth
                .dmarc_from
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or(from_domain);
            push_reason(&mut reasons, &format!("DMARC failed for {dom}"));
        } else if !auth.dmarc_pass
            && !aligned_spf_or_dkim(auth, from_domain, &from_org)
        {
            push_reason(&mut reasons, "no DMARC and no aligned SPF/DKIM pass");
        }
        if auth.spf_fail && !dkim_aligned_pass(auth, from_domain, &from_org) {
            push_reason(&mut reasons, "SPF failed");
        }
    }

    for link in links.iter().take(256) {
        check_link(link, &mut reasons);
    }

    let level = compute_level(
        &reasons,
        trusted_auth.as_ref(),
        pm.spam_action.as_deref(),
        pm.origin.as_deref(),
        from_domain,
        &from_org,
    );

    let summary = build_summary(level, &reasons);
    if reasons.len() > MAX_REASONS {
        reasons.truncate(MAX_REASONS);
    }
    Verdict {
        level,
        summary,
        reasons,
    }
}

fn push_reason(reasons: &mut Vec<String>, s: &str) {
    if reasons.len() < MAX_REASONS && !reasons.iter().any(|r| r == s) {
        reasons.push(s.to_string());
    }
}

fn compute_level(
    reasons: &[String],
    auth: Option<&TrustedAuth>,
    spam_action: Option<&str>,
    origin: Option<&str>,
    from_domain: &str,
    from_org: &str,
) -> Level {
    let spf_danger = reasons.iter().any(|r| r == "SPF failed")
        && auth.is_some_and(|a| a.spf_fail && !dkim_aligned_pass(a, from_domain, from_org));
    let danger = spam_action == Some("phishing")
        || spf_danger
        || reasons.iter().any(|r| {
            r.contains("phishing")
                || r.contains("forged")
                || r.starts_with("DMARC failed")
                || r.starts_with("link text shows")
        });
    if danger {
        return Level::Danger;
    }

    let caution = spam_action == Some("spam")
        || reasons.iter().any(|r| {
            r.contains("spam")
                || r.starts_with("Reply-To")
                || r.contains("display name")
                || r.contains("punycode")
                || r.contains("mixes scripts")
                || r.starts_with("link points to")
                || r.starts_with("no DMARC")
        });
    if caution {
        return Level::Caution;
    }

    if auth.is_some_and(|a| a.dmarc_pass) {
        return Level::Pass;
    }
    if origin == Some("internal") {
        return Level::Pass;
    }
    if auth.is_some_and(|a| aligned_spf_or_dkim(a, from_domain, from_org)) {
        return Level::Pass;
    }

    if auth.is_none() {
        return Level::Unverified;
    }
    Level::Unverified
}

fn build_summary(level: Level, reasons: &[String]) -> String {
    let mut s = String::from("Sender check: ");
    s.push_str(level.as_str());
    s.push_str(" (");
    if reasons.is_empty() {
        match level {
            Level::Pass => s.push_str("authentication OK"),
            Level::Unverified => s.push_str("no authentication results"),
            _ => s.push_str("see reasons"),
        }
    } else {
        for (i, r) in reasons.iter().take(8).enumerate() {
            if i > 0 {
                s.push_str("; ");
            }
            let short = if r.starts_with("DMARC failed for ") {
                format!("DMARC failed for {}", r.trim_start_matches("DMARC failed for "))
            } else if r == "Proton flagged phishing" {
                "Proton flagged phishing".to_string()
            } else if r == "SPF failed" {
                "SPF failed".to_string()
            } else {
                r.clone()
            };
            let _ = write!(s, "{short}");
        }
    }
    s.push(')');
    s
}

#[derive(Debug, Clone)]
struct Addr {
    display: String,
    domain: String,
}

#[derive(Debug, Clone, Default)]
struct TrustedAuth {
    dmarc_pass: bool,
    dmarc_fail: bool,
    dmarc_from: Option<String>,
    spf_pass: bool,
    spf_fail: bool,
    /// smtp.mailfrom domains of passing SPF results.
    spf_pass_domains: Vec<String>,
    dkim_pass_domains: Vec<String>,
    dkim_pass_any: bool,
}

#[derive(Debug, Clone, Default)]
struct ProtonMeta {
    spam_action: Option<String>,
    origin: Option<String>,
    forged_pm_headers: bool,
}

fn unfold_headers(raw: &[u8]) -> Vec<Vec<u8>> {
    let norm = normalize_crlf(raw);
    let mut lines: Vec<Vec<u8>> = Vec::new();
    for line in norm.split(|&b| b == b'\n') {
        let line = if line.len() > MAX_LINE {
            &line[..MAX_LINE]
        } else {
            line
        };
        if let Some(last) = lines.last_mut()
            && line.first().is_some_and(|b| *b == b' ' || *b == b'\t')
        {
            last.push(b' ');
            last.extend(trim_ascii_bytes(line));
            continue;
        }
        lines.push(line.to_vec());
    }
    lines
}

fn normalize_crlf(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'\r' {
            out.push(b'\n');
            if i + 1 < input.len() && input[i + 1] == b'\n' {
                i += 2;
            } else {
                i += 1;
            }
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    out
}

fn trim_ascii_bytes(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|&b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|&b| !b.is_ascii_whitespace())
        .map_or(start, |i| i + 1);
    bytes.get(start..end).unwrap_or(&[])
}

fn header_name_eq(line: &[u8], name: &[u8]) -> bool {
    let Some(colon) = line.iter().position(|&b| b == b':') else {
        return false;
    };
    let h = trim_ascii_bytes(&line[..colon]);
    h.len() == name.len() && h.iter().zip(name.iter()).all(|(a, b)| a.eq_ignore_ascii_case(b))
}

fn header_value_line(line: &[u8]) -> &str {
    let Some(colon) = line.iter().position(|&b| b == b':') else {
        return "";
    };
    let v = trim_ascii_bytes(&line[colon + 1..]);
    std::str::from_utf8(v).unwrap_or("")
}

/// Proton's own results: Authentication-Results whose authserv-id is a protonmail.ch host. Bridge
/// does not keep them in a fixed position (older mail has them below the Received headers), so
/// position is not used; `proton_auth_inconsistent` catches planted copies instead.
fn parse_trusted_auth(lines: &[Vec<u8>]) -> Option<TrustedAuth> {
    let mut auth = TrustedAuth::default();
    let mut any_trusted = false;
    for val in proton_auth_values(lines) {
        any_trusted = true;
        merge_auth_results(&mut auth, val);
    }
    any_trusted.then_some(auth)
}

fn proton_auth_values(lines: &[Vec<u8>]) -> impl Iterator<Item = &str> {
    lines.iter().filter(|l| header_name_eq(l, b"authentication-results")).filter_map(|l| {
        let val = header_value_line(l);
        let authserv = val.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
        authserv.ends_with(".protonmail.ch").then_some(val)
    })
}

/// A message is treated as carrying planted "Proton" results when its protonmail.ch results come
/// from more than one receiving host, or disagree with each other on SPF or DMARC. Proton's real
/// results for one delivery come from one host and agree.
fn proton_auth_inconsistent(lines: &[Vec<u8>]) -> bool {
    let mut hosts: Vec<String> = Vec::new();
    let mut verdicts: Vec<(&'static str, String)> = Vec::new();
    for val in proton_auth_values(lines) {
        let lower = val.to_ascii_lowercase();
        let mut parts = lower.split(';');
        let host = parts.next().unwrap_or("").trim().to_string();
        if !hosts.contains(&host) {
            hosts.push(host);
        }
        for part in parts {
            let p = part.trim();
            for method in ["spf", "dmarc"] {
                if let Some(rest) = p.strip_prefix(method).and_then(|r| r.strip_prefix('=')) {
                    let result: String = rest.chars().take_while(|c| c.is_ascii_alphanumeric()).collect();
                    if verdicts.iter().any(|(m, r)| *m == method && *r != result) {
                        return true;
                    }
                    verdicts.push((method, result));
                }
            }
        }
    }
    hosts.len() > 1
}

fn merge_auth_results(auth: &mut TrustedAuth, val: &str) {
    let lower = val.to_ascii_lowercase();
    for part in lower.split(';') {
        let p = part.trim();
        if p.starts_with("dmarc=pass") {
            auth.dmarc_pass = true;
            if let Some(d) = extract_header_domain(part, "header.from") {
                auth.dmarc_from = Some(d);
            }
        } else if p.starts_with("dmarc=fail") {
            auth.dmarc_fail = true;
            if let Some(d) = extract_header_domain(part, "header.from") {
                auth.dmarc_from = Some(d);
            }
        }
        if p.starts_with("spf=pass") {
            auth.spf_pass = true;
            if let Some(d) = extract_header_domain(part, "smtp.mailfrom") {
                // smtp.mailfrom may be a full address.
                let d = d.rsplit_once('@').map_or(d.as_str(), |(_, dom)| dom).to_string();
                auth.spf_pass_domains.push(d);
            }
        } else if p.starts_with("spf=fail") {
            auth.spf_fail = true;
        }
        if p.starts_with("dkim=pass") {
            auth.dkim_pass_any = true;
            if let Some(d) = extract_header_domain(part, "header.d") {
                auth.dkim_pass_domains.push(d);
            }
        }
    }
}

fn extract_header_domain(part: &str, key: &str) -> Option<String> {
    let lower = part.to_ascii_lowercase();
    let key = key.to_ascii_lowercase();
    let pos = lower.find(&key)?;
    let rest = part.get(pos + key.len()..)?;
    let rest = rest.trim_start_matches('=').trim();
    let dom = rest
        .split_whitespace()
        .next()?
        .trim_matches('"')
        .to_ascii_lowercase();
    if dom.is_empty() {
        None
    } else {
        Some(dom)
    }
}

fn parse_proton_appended(lines: &[Vec<u8>]) -> ProtonMeta {
    let mut actions: Vec<String> = Vec::new();
    let mut origins: Vec<String> = Vec::new();
    let mut scores: Vec<String> = Vec::new();

    for line in lines {
        if header_name_eq(line, b"x-pm-spam-action") {
            actions.push(header_value_line(line).trim().to_ascii_lowercase());
        } else if header_name_eq(line, b"x-pm-origin") {
            origins.push(header_value_line(line).trim().to_ascii_lowercase());
        } else if header_name_eq(line, b"x-pm-spamscore") {
            scores.push(header_value_line(line).trim().to_string());
        }
    }

    let forged = unique_values_conflict(&actions)
        || unique_values_conflict(&origins)
        || unique_values_conflict(&scores);

    ProtonMeta {
        spam_action: actions.last().cloned(),
        origin: origins.last().cloned(),
        forged_pm_headers: forged,
    }
}

fn unique_values_conflict(values: &[String]) -> bool {
    if values.len() < 2 {
        return false;
    }
    let last = values.last();
    values
        .iter()
        .take(values.len().saturating_sub(1))
        .any(|v| Some(v) != last)
}

fn parse_from_reply(lines: &[Vec<u8>], name: &[u8]) -> Option<Addr> {
    let mut last = None;
    for line in lines {
        if header_name_eq(line, name) {
            last = Some(header_value_line(line).to_string());
        }
    }
    let raw = last?;
    parse_address_header(&raw)
}

fn parse_address_header(raw: &str) -> Option<Addr> {
    let raw = raw.trim();
    let angle_start = raw.rfind('<');
    let angle_end = raw.rfind('>');
    let (display, addr_part) = if let (Some(s), Some(e)) = (angle_start, angle_end) {
        if s < e {
            (
                raw.get(..s).unwrap_or("").trim().trim_matches('"').to_string(),
                raw.get(s + 1..e).unwrap_or("").trim(),
            )
        } else {
            (String::new(), raw)
        }
    } else {
        (String::new(), raw)
    };
    let at = addr_part.rfind('@')?;
    let domain = addr_part.get(at + 1..)?.trim().to_ascii_lowercase();
    if domain.is_empty() {
        return None;
    }
    Some(Addr { display, domain })
}

/// Organizational domain (approximation per SECURITY-CHECKS.md).
pub fn org_domain(domain: &str) -> String {
    let d = domain.trim();
    let d = d.rsplit_once('@').map_or(d, |(_, dom)| dom);
    let d = d.trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() {
        return String::new();
    }
    let labels: Vec<&str> = d.split('.').filter(|s| !s.is_empty()).collect();
    if labels.is_empty() {
        return d;
    }
    if labels.len() >= 3 {
        let second = labels[labels.len() - 2];
        let last = labels[labels.len() - 1];
        const SLD: &[&str] = &["co", "com", "net", "org", "gov", "ac", "edu"];
        if SLD.contains(&second) && last.len() == 2 {
            return format!("{}.{}.{}", labels[labels.len() - 3], second, last);
        }
    }
    if labels.len() >= 2 {
        format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1])
    } else {
        d
    }
}

fn dkim_aligned_pass(auth: &TrustedAuth, from_domain: &str, from_org: &str) -> bool {
    if from_domain.is_empty() {
        return false;
    }
    for d in &auth.dkim_pass_domains {
        if domains_align(d, from_domain) || domains_align(d, from_org) {
            return true;
        }
        if org_domain(d) == from_org && !from_org.is_empty() {
            return true;
        }
    }
    false
}

fn aligned_spf_or_dkim(auth: &TrustedAuth, from_domain: &str, from_org: &str) -> bool {
    if auth.dmarc_pass {
        return true;
    }
    // SPF only counts when the envelope sender's domain matches the From domain (DMARC alignment).
    if !from_domain.is_empty() && auth.spf_pass_domains.iter().any(|d| domains_align(d, from_domain)) {
        return true;
    }
    dkim_aligned_pass(auth, from_domain, from_org)
}

fn domains_align(a: &str, b: &str) -> bool {
    let a = a.trim().to_ascii_lowercase();
    let b = b.trim().to_ascii_lowercase();
    a == b || org_domain(&a) == org_domain(&b)
}

fn domain_is_punycode(domain: &str) -> bool {
    domain.to_ascii_lowercase().contains("xn--")
}

fn script_bucket(c: char) -> u8 {
    if c.is_ascii_alphabetic() {
        1
    } else if ('\u{0400}'..='\u{04FF}').contains(&c) {
        2
    } else if ('\u{0370}'..='\u{03FF}').contains(&c) {
        3
    } else if ('\u{0590}'..='\u{05FF}').contains(&c) {
        4
    } else if ('\u{0600}'..='\u{06FF}').contains(&c) {
        5
    } else if ('\u{4E00}'..='\u{9FFF}').contains(&c) {
        6
    } else {
        0
    }
}

fn domain_mixed_script(domain: &str) -> bool {
    let mut seen = 0u8;
    for c in domain.chars() {
        let b = script_bucket(c);
        if b == 0 {
            continue;
        }
        seen |= 1 << b;
        if seen.count_ones() > 1 {
            return true;
        }
    }
    false
}

fn alnum_lower(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        }
    }
    if out.len() > MAX_EDIT_LABEL {
        out.truncate(MAX_EDIT_LABEL);
    }
    out
}

fn label_from_domain(domain: &str) -> String {
    let d = domain.trim().to_ascii_lowercase();
    let host = d.split('@').next().unwrap_or(&d);
    host.split('.')
        .next()
        .unwrap_or(host)
        .to_string()
}

fn display_name_lookalike(addr: &Addr) -> bool {
    let disp = alnum_lower(&addr.display);
    if disp.is_empty() || disp.len() < 3 {
        return false;
    }
    let label = alnum_lower(&label_from_domain(&addr.domain));
    if label.is_empty() {
        return false;
    }
    if disp == label {
        return false;
    }
    let dist = edit_distance(&disp, &label);
    dist == 1 || dist == 2
}

fn display_name_domain_mismatch(addr: &Addr) -> bool {
    let d = addr.display.trim();
    if d.is_empty() {
        return false;
    }
    if d.contains('@')
        && let Some(inner) = parse_address_header(d)
    {
        return !domains_align(&inner.domain, &addr.domain);
    }
    if let Some(dom) = domain_like_in_text(d) {
        return !domains_align(&dom, &addr.domain);
    }
    false
}

fn domain_like_in_text(s: &str) -> Option<String> {
    for word in s.split_whitespace() {
        let w = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '.' && c != '-');
        if w.contains('.') && !w.starts_with('.') {
            let parts: Vec<_> = w.split('.').collect();
            if parts.len() >= 2 && parts.iter().all(|p| !p.is_empty()) {
                return Some(w.to_ascii_lowercase());
            }
        }
    }
    None
}

fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let n = a.len();
    let m = b.len();
    if n == 0 {
        return m;
    }
    if m == 0 {
        return n;
    }
    let mut prev: Vec<usize> = (0..=m).collect();
    let mut curr = vec![0usize; m + 1];
    for (i, ca) in a.iter().enumerate() {
        curr[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            curr[j + 1] = (prev[j + 1] + 1)
                .min(curr[j] + 1)
                .min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[m]
}

fn check_link(link: &Link, reasons: &mut Vec<String>) {
    let href = link.href.trim();
    let text = link.text.trim();
    if href.is_empty() {
        return;
    }
    let lower = href.to_ascii_lowercase();
    if lower.starts_with("javascript:") || lower.starts_with("data:") {
        push_reason(
            reasons,
            &format!("link points to suspicious URL scheme ({href})"),
        );
        return;
    }
    if let Some(host) = host_from_href(href) {
        if looks_like_ipv4(&host) {
            push_reason(reasons, &format!("link points to raw IP address ({host})"));
        }
        if host.contains("xn--") {
            push_reason(reasons, &format!("link points to punycode host ({host})"));
        }
        if let Some(text_dom) = domain_from_link_text(text) {
            let href_org = org_domain(&host);
            let text_org = org_domain(&text_dom);
            if !text_dom.is_empty()
                && !host.is_empty()
                && text_org != href_org
                && !host.ends_with(&text_dom)
                && !text_dom.ends_with(&host)
            {
                push_reason(
                    reasons,
                    &format!("link text shows {text_dom} but href points to {host}"),
                );
            }
        }
    }
}

fn looks_like_ipv4(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}

fn host_from_href(href: &str) -> Option<String> {
    let h = href.trim();
    let rest = h
        .strip_prefix("https://")
        .or_else(|| h.strip_prefix("http://"))
        .or_else(|| h.strip_prefix("//"))
        .unwrap_or(h);
    let host = rest.split(['/', '?', '#']).next()?.trim();
    let host = host.split('@').next().unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host).to_ascii_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

fn domain_from_link_text(text: &str) -> Option<String> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    if let Some(d) = domain_like_in_text(t) {
        return Some(d);
    }
    let compact: String = t
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '.')
        .collect();
    if compact.contains('.') {
        return Some(compact.to_ascii_lowercase());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_phishing() -> Vec<u8> {
        concat!(
            "From: \"PayPal\" <user@webmail.example>\r\n",
            "Reply-To: scammer@evil.ru\r\n",
            "Authentication-Results: mailin008.protonmail.ch; dkim=pass (Good 1024 bit rsa-sha256 signature) header.d=relay-isp.example header.a=rsa-sha256\r\n",
            "Authentication-Results: mailin008.protonmail.ch; dmarc=fail (p=none dis=none) header.from=webmail.example\r\n",
            "Authentication-Results: mailin008.protonmail.ch; spf=fail smtp.mailfrom=webmail.example\r\n",
            "Authentication-Results: mailin008.protonmail.ch; arc=none smtp.remote-ip=192.0.2.27\r\n",
            "Received: from mail.example.com by proton\r\n",
            "X-Pm-Spamscore: 101\r\n",
            "X-Pm-Spam-Action: phishing\r\n",
            "X-Pm-Origin: external\r\n",
        )
        .as_bytes()
        .to_vec()
    }

    fn fixture_pass() -> Vec<u8> {
        concat!(
            "From: notices@esign.example\r\n",
            "Authentication-Results: mailin008.protonmail.ch; dmarc=pass (p=reject dis=none) header.from=esign.example\r\n",
            "Authentication-Results: mailin008.protonmail.ch; spf=pass smtp.mailfrom=esign.example\r\n",
            "Authentication-Results: mailin008.protonmail.ch; dkim=pass header.d=esign.example\r\n",
            "Received: from mx.proton\r\n",
            "X-Pm-Spam-Action: inbox\r\n",
            "X-Pm-Origin: external\r\n",
        )
        .as_bytes()
        .to_vec()
    }

    fn fixture_spam() -> Vec<u8> {
        concat!(
            "From: promo@deals.example.com\r\n",
            "Authentication-Results: mailin008.protonmail.ch; dmarc=none header.from=deals.example.com\r\n",
            "Authentication-Results: mailin008.protonmail.ch; spf=pass smtp.mailfrom=deals.example.com\r\n",
            "Received: from somewhere\r\n",
            "X-Pm-Spam-Action: spam\r\n",
            "X-Pm-Origin: external\r\n",
        )
        .as_bytes()
        .to_vec()
    }

    #[test]
    fn org_domain_uk() {
        assert_eq!(org_domain("mail.example.co.uk"), "example.co.uk");
        assert_eq!(org_domain("user@foo.com"), "foo.com");
    }

    #[test]
    fn proton_results_below_received_are_trusted() {
        // Older Bridge mail: Proton's results sit after the Received headers.
        let raw = concat!(
            "From: Stripe <receipts@payments.example>\r\n",
            "Received: from out1.mailer-cloud.example by mailin013.protonmail.ch\r\n",
            "Received: by sender-internal-relay\r\n",
            "Authentication-Results: mailin013.protonmail.ch; dmarc=pass (p=reject dis=none) header.from=payments.example\r\n",
            "Authentication-Results: mailin013.protonmail.ch; spf=pass smtp.mailfrom=bounce.payments.example\r\n",
            "Authentication-Results: mailin013.protonmail.ch; dkim=pass header.d=payments.example\r\n",
            "X-Pm-Spam-Action: dunno\r\n",
        );
        let v = check(raw.as_bytes(), &[]);
        assert_eq!(v.level, Level::Pass, "{:?}", v.reasons);
    }

    #[test]
    fn planted_proton_results_are_danger() {
        // A second "Proton" host, or a pass that contradicts Proton's fail, means a planted header.
        let two_hosts = concat!(
            "From: a@bank.example\r\n",
            "Authentication-Results: mailin008.protonmail.ch; dmarc=fail header.from=bank.example\r\n",
            "Authentication-Results: mailin999.protonmail.ch; dmarc=fail header.from=bank.example\r\n",
        );
        let v = check(two_hosts.as_bytes(), &[]);
        assert_eq!(v.level, Level::Danger);
        assert!(v.reasons.iter().any(|r| r.contains("forged")), "{:?}", v.reasons);
        let contradicting = concat!(
            "From: a@bank.example\r\n",
            "Authentication-Results: mailin008.protonmail.ch; dmarc=pass header.from=bank.example\r\n",
            "Received: from x\r\n",
            "Authentication-Results: mailin008.protonmail.ch; dmarc=fail header.from=bank.example\r\n",
        );
        let v = check(contradicting.as_bytes(), &[]);
        assert_eq!(v.level, Level::Danger);
        assert!(v.reasons.iter().any(|r| r.contains("forged")), "{:?}", v.reasons);
    }

    #[test]
    fn ignore_non_proton_authserv() {
        let raw = concat!(
            "Authentication-Results: evil.com; dmarc=fail header.from=bad.com\r\n",
            "Received: from x\r\n",
        );
        let v = check(raw.as_bytes(), &[]);
        assert_eq!(v.level, Level::Unverified);
    }

    #[test]
    fn forged_pm_headers_last_wins() {
        let raw = concat!(
            "X-Pm-Spam-Action: inbox\r\n",
            "Received: from x\r\n",
            "X-Pm-Spam-Action: phishing\r\n",
        );
        let v = check(raw.as_bytes(), &[]);
        assert!(v.reasons.iter().any(|r| r.contains("forged Proton")));
        assert!(v.reasons.iter().any(|r| r.contains("phishing")));
    }

    #[test]
    fn pm_spam_action_last_instance() {
        let v = check(b"X-Pm-Spam-Action: spam\r\n", &[]);
        assert!(v.reasons.iter().any(|r| r.contains("spam")));
        assert_eq!(v.level, Level::Caution);
        // Two differing copies: the sender planted one, so this is a forgery.
        let v = check(b"X-Pm-Spam-Action: inbox\r\nX-Pm-Spam-Action: spam\r\n", &[]);
        assert_eq!(v.level, Level::Danger, "{:?}", v.reasons);
    }

    #[test]
    fn dmarc_fail_is_danger() {
        let raw = concat!(
            "From: a@webmail.example\r\n",
            "Authentication-Results: mailin008.protonmail.ch; dmarc=fail header.from=webmail.example\r\n",
        );
        let v = check(raw.as_bytes(), &[]);
        assert_eq!(v.level, Level::Danger);
        assert!(v.reasons.iter().any(|r| r.contains("DMARC failed")));
    }

    #[test]
    fn spf_fail_without_dkim_align_is_danger() {
        let raw = concat!(
            "From: user@brand.com\r\n",
            "Authentication-Results: mailin008.protonmail.ch; spf=fail smtp.mailfrom=brand.com\r\n",
            "Authentication-Results: mailin008.protonmail.ch; dkim=pass header.d=other.com\r\n",
        );
        let v = check(raw.as_bytes(), &[]);
        assert_eq!(v.level, Level::Danger);
    }

    #[test]
    fn link_text_href_mismatch_danger() {
        let raw = "From: a@b.com\r\n";
        let links = vec![Link {
            text: "www.paypal.com".to_string(),
            href: "https://evil.ru/steal".to_string(),
        }];
        let v = check(raw.as_bytes(), &links);
        assert_eq!(v.level, Level::Danger);
        assert!(v.reasons.iter().any(|r| r.starts_with("link text shows")));
    }

    #[test]
    fn link_ip_javascript_caution() {
        let raw = "From: a@b.com\r\n";
        let links = vec![
            Link {
                text: "click".to_string(),
                href: "http://192.168.1.1/path".to_string(),
            },
            Link {
                text: "x".to_string(),
                href: "javascript:alert(1)".to_string(),
            },
        ];
        let v = check(raw.as_bytes(), &links);
        assert_eq!(v.level, Level::Caution);
    }

    #[test]
    fn reply_to_different_org_caution() {
        let raw = concat!(
            "From: a@company.com\r\n",
            "Reply-To: b@other.org\r\n",
            "Authentication-Results: mailin008.protonmail.ch; dmarc=pass header.from=company.com\r\n",
        );
        let v = check(raw.as_bytes(), &[]);
        assert_eq!(v.level, Level::Caution);
        assert!(v.reasons.iter().any(|r| r.starts_with("Reply-To")));
    }

    #[test]
    fn display_lookalike_caution() {
        let raw = "From: \"PayPal\" <noreply@paypa1.com>\r\n";
        let v = check(raw.as_bytes(), &[]);
        assert!(v.reasons.iter().any(|r| r.contains("display name resembles")));
    }

    #[test]
    fn punycode_from_caution() {
        let raw = "From: a@xn--paypal-abc.com\r\n";
        let v = check(raw.as_bytes(), &[]);
        assert!(v.reasons.iter().any(|r| r.contains("punycode")));
    }

    #[test]
    fn no_auth_unverified() {
        let v = check(b"From: a@b.com\r\n", &[]);
        assert_eq!(v.level, Level::Unverified);
        assert!(v.summary.contains("no authentication results"));
    }

    #[test]
    fn internal_origin_pass() {
        let raw = concat!(
            "From: me@pm.me\r\n",
            "X-Pm-Origin: internal\r\n",
        );
        let v = check(raw.as_bytes(), &[]);
        assert_eq!(v.level, Level::Pass);
    }

    #[test]
    fn fixture_phishing_real_headers() {
        let v = check(&fixture_phishing(), &[]);
        assert_eq!(v.level, Level::Danger);
        assert!(v.summary.contains("DANGER"));
        assert!(v.reasons.iter().any(|r| r.contains("phishing")));
        assert!(v.reasons.iter().any(|r| r.contains("DMARC failed")));
    }

    #[test]
    fn fixture_pass_real_headers() {
        let v = check(&fixture_pass(), &[]);
        assert_eq!(v.level, Level::Pass);
        assert!(v.summary.contains("PASS"));
    }

    #[test]
    fn fixture_spam_real_headers() {
        let v = check(&fixture_spam(), &[]);
        assert_eq!(v.level, Level::Caution);
        assert!(v.reasons.iter().any(|r| r.contains("spam")));
    }

    #[test]
    fn arbitrary_bytes_no_panic() {
        let mut rng = 1u32;
        for _ in 0..5000 {
            rng ^= rng << 13;
            rng ^= rng >> 17;
            rng ^= rng << 5;
            let len = (rng as usize % 800) + 1;
            let mut buf = vec![0u8; len];
            for b in &mut buf {
                rng ^= rng << 13;
                rng ^= rng >> 17;
                rng ^= rng << 5;
                *b = rng as u8;
            }
            let _ = check(&buf, &[Link {
                text: String::from_utf8_lossy(&buf[..buf.len().min(20)]).into_owned(),
                href: String::from_utf8_lossy(&buf[..buf.len().min(40)]).into_owned(),
            }]);
        }
    }

    #[test]
    fn mixed_script_domain_caution() {
        let raw = "From: a@\u{0430}mazon.com\r\n";
        let v = check(raw.as_bytes(), &[]);
        assert!(v.reasons.iter().any(|r| r.contains("mixes scripts")));
    }

    #[test]
    fn pm_origin_forgery_danger() {
        let raw = "X-Pm-Origin: internal\r\nX-Pm-Origin: external\r\n";
        let v = check(raw.as_bytes(), &[]);
        assert!(v.reasons.iter().any(|r| r.contains("forged Proton")));
    }

    #[test]
    fn display_name_embedded_email_mismatch() {
        let raw = "From: \"billing@paypal.com\" <shop@notpaypal.com>\r\n";
        let v = check(raw.as_bytes(), &[]);
        assert!(v.reasons.iter().any(|r| r.contains("display name suggests")));
    }

    #[test]
    fn dmarc_pass_aligned_rule() {
        let raw = concat!(
            "From: a@brand.co.uk\r\n",
            "Authentication-Results: mailin001.protonmail.ch; dmarc=pass header.from=brand.co.uk\r\n",
        );
        let v = check(raw.as_bytes(), &[]);
        assert_eq!(v.level, Level::Pass);
    }

    #[test]
    fn edit_distance_rule() {
        assert_eq!(edit_distance("paypal", "paypa1"), 1);
        assert!(display_name_lookalike(&Addr {
            display: "PayPal".to_string(),
            domain: "paypa1.com".to_string(),
        }));
    }

    #[test]
    fn spf_pass_for_another_domain_is_not_alignment() {
        // Bulk mailer: SPF passes for the mailer's bounce domain, From is someone else, no DKIM.
        let h = concat!(
            "From: Brand <news@brand.example>\r\n",
            "Authentication-Results: mailin001.protonmail.ch; dmarc=none (p=none dis=none) header.from=brand.example\r\n",
            "Authentication-Results: mailin001.protonmail.ch; spf=pass smtp.mailfrom=bounces.mailer.example\r\n",
            "Authentication-Results: mailin001.protonmail.ch; dkim=none\r\n",
            "Received: from x\r\n",
            "X-Pm-Spam-Action: inbox\r\n",
        );
        let v = check(h.as_bytes(), &[]);
        assert_ne!(v.level, Level::Pass, "{}", v.summary);
        let aligned = h.replace("smtp.mailfrom=bounces.mailer.example", "smtp.mailfrom=bounce@mail.brand.example");
        assert_eq!(check(aligned.as_bytes(), &[]).level, Level::Pass);
    }

    #[test]
    fn no_from_never_aligns() {
        let h = concat!(
            "Authentication-Results: mailin001.protonmail.ch; dkim=pass header.d=any.example\r\n",
            "Received: from x\r\n",
        );
        assert_ne!(check(h.as_bytes(), &[]).level, Level::Pass);
    }
}
