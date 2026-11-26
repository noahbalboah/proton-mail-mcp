# Sender and phishing checks (v0.2)

The goal is to tell the agent, for every message, whether the sender is who they claim to be and
whether the message shows common phishing signs. The checks are pure analysis of headers and HTML,
with no network lookups and no new crates. The result is advice for the agent: nothing is blocked.

## What Proton Mail Bridge exposes (verified on a live mailbox, Bridge 3.27.2)

Header order as Bridge returns it:

```
X-Pm-Gluon-Id, Content-Type, References, X-Pm-Date, X-Pm-External-Id, X-Pm-Internal-Id, To,
Reply-To, From, Return-Path, X-Original-To, Delivered-To,
Authentication-Results  x4-6     <- Proton's inbound MTA (authserv-id mailinNNN.protonmail.ch)
Received ...                     <- first Received: everything below is the sender's original header
... original headers (may include forged Authentication-Results / X-Pm-* lines) ...
X-Spamd-Result, X-Rspamd-*, X-Pm-Spam, X-Pm-Origin, X-Pm-Transfer-Encryption,
X-Pm-Content-Encryption, X-Pm-Spamscore, X-Pm-Spam-Action      <- Proton, appended at the end
```

Real examples:

```
Authentication-Results: mailin008.protonmail.ch; dkim=pass (Good 1024 bit rsa-sha256 signature) header.d=relay-isp.example header.a=rsa-sha256
Authentication-Results: mailin008.protonmail.ch; dmarc=fail (p=none dis=none) header.from=webmail.example
Authentication-Results: mailin008.protonmail.ch; spf=fail smtp.mailfrom=webmail.example
Authentication-Results: mailin008.protonmail.ch; arc=none smtp.remote-ip=192.0.2.27
Authentication-Results: mailin008.protonmail.ch; dkim=pass (1024-bit key) header.d=relay-isp.example header.i=@relay-isp.example header.b="AbCdEf12"
X-Pm-Spamscore: 101
X-Pm-Spam-Action: phishing          (seen values: inbox, spam, phishing)
X-Pm-Origin: external               (or internal for Proton-to-Proton)
```

A single Authentication-Results line can hold several results separated by `;`, for example
`dkim=pass ... ; dkim=pass ...`. Header folding sometimes appears as runs of spaces inside the
value.

## Trust rules

1. **Authentication-Results:** use instances whose authserv-id (the first token, before `;`)
   ends in `.protonmail.ch`. Their position is **not** fixed: in recent mail they sit above the
   first `Received`, but in older mail Bridge places them after the Received headers (including
   the sender's own relays), so position cannot separate real from planted copies. Instead, a
   message is flagged "forged authentication headers" (Danger) when its protonmail.ch results
   come from more than one receiving host (`mailin013` and `mailin999`), or disagree on SPF or
   DMARC (`dmarc=pass` next to `dmarc=fail`). Proton's real results for one delivery come from one
   host and agree. A forger who copies the right host and Proton's real verdict gains nothing.
2. **X-Pm-Spam-Action, X-Pm-Spamscore, X-Pm-Origin:** use the **last** instance of each. If an
   earlier instance has a different value, flag forged Proton headers (Danger).
3. If there is no trusted Authentication-Results at all, the result is `Unverified`, with no
   claims either way. Drafts and sent mail have none.

## Verdict

`Verdict { level: Level, summary: String, reasons: Vec<String> }`, where
`Level = Pass | Caution | Danger | Unverified`. Reasons are short and plain, such as
"DMARC failed for webmail.example" or "Reply-To goes to a different domain (x.ru)".

- **Danger** if any of:
  - Proton's spam action is `phishing`;
  - DMARC fail;
  - forged Proton headers;
  - SPF fail and DKIM not passing for the From domain;
  - a link whose visible text shows one domain while the link points to another (HTML).
- **Caution** if any of:
  - spam action is `spam`;
  - DMARC none or absent and nothing aligned passed (no SPF or DKIM pass whose domain matches the
    From domain's organizational domain);
  - Reply-To on a different organizational domain than From;
  - the display name contains an email address or domain that differs from the From domain;
  - the From domain is punycode (`xn--`) or mixes scripts;
  - the display name looks like the From domain's label but isn't it (edit distance 1 or 2 after
    lowercasing and removing non-alphanumerics, e.g. display "PayPal" from `paypa1.com`);
  - links to a raw IP address, a punycode host, or `javascript:`/`data:` URLs.
- **Pass:** DMARC pass, or (Proton origin `internal` with no Danger/Caution reasons), or an
  aligned DKIM/SPF pass with no Caution reasons.
- Otherwise **Unverified**.

Organizational domain approximation: take the last two labels, or the last three when the
second-to-last label is one of `co com net org gov ac edu` and the last label has two letters
(`example.co.uk`). It's simple, and it's documented as an approximation.

Summary line examples:

```
Sender check: PASS (DMARC pass for esign.example)
Sender check: DANGER (Proton flagged phishing; DMARC failed for webmail.example; SPF failed)
Sender check: CAUTION (no DMARC; Reply-To goes to a different domain: x.ru)
Sender check: UNVERIFIED (no authentication results)
```

## API (security.rs, pure, no IO)

```rust
pub enum Level { Pass, Caution, Danger, Unverified }
pub struct Verdict { pub level: Level, pub summary: String, pub reasons: Vec<String> }
/// `raw_headers`: the header section exactly as fetched (CRLF, folded). Works on a full header or on a
/// HEADER.FIELDS subset that keeps original order.
pub fn check(raw_headers: &[u8], links: &[Link]) -> Verdict
pub struct Link { pub text: String, pub href: String }
```

In mime.rs, add `pub fn html_links(raw_message: &[u8], max: usize) -> Vec<Link>`: walk the same
parts, take the HTML body, collect `<a href=...>visible text</a>` (attribute quoting variants,
entities decoded, text whitespace collapsed), capped at `max`, in linear time. Also add
`pub fn header_section(raw: &[u8]) -> &[u8]` if no equivalent exists.

Every function must survive arbitrary bytes without panicking. Each rule above gets a unit
test, plus the three real header sets above (pass, phishing, spam) as fixtures.
