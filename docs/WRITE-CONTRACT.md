# Write-access contract (v0.2)

Design decisions: the agent may organize mail. **Delete = move to Trash only; nothing is
ever permanently erased.** Drafts only (APPEND to Drafts, no SMTP). Also: read/unread + star,
create folders/labels, read attachment text, audit log of every change.

Threat model: email content is attacker-written. The agent may be tricked into calling write tools.
So the server, not the agent, must make permanent loss impossible and keep every change reversible.

## Proton Bridge IMAP semantics (verified: CAPABILITY ... MOVE UIDPLUS UNSELECT IDLE)

- Each message lives in exactly one folder: `INBOX`, `Archive`, `Spam`, `Trash`, `Sent`, `Drafts`,
  or `Folders/<name>`; plus any number of labels, shown as mailboxes `Labels/<name>`. `All Mail`
  and `Starred` are virtual.
- Add a label: `UID COPY <set> "Labels/X"` from any mailbox.
- Remove a label: in `Labels/X`, `UID STORE <set> +FLAGS.SILENT (\Deleted)` then
  `UID EXPUNGE <set>`. In a label mailbox this removes only the label.
- Anywhere else, `\Deleted` + EXPUNGE can permanently delete. **Never allowed outside `Labels/`.**
- EXPUNGE in Trash or Drafts is a permanent delete. MOVE to Trash deletes nothing.
- Reported Bridge bug: one message in two folders (Inbox and Sent) moved to Trash twice was then
  permanently deleted. Guard: `trash_messages` first runs `UID SEARCH HEADER MESSAGE-ID` for each
  Message-ID in Trash and skips any that are already there.
- Bridge drops In-Reply-To/References on APPEND, so a draft won't thread. That is accepted; say
  so in the tool description.
- Move and trash sources are real folders only: `INBOX`, `Archive`, `Spam`, `Sent`, `Drafts`,
  `Folders/*`. Never `All Mail`, `Starred`, `Labels/*` (Bridge semantics there are unclear) or
  `Trash` (moving out of Trash is allowed only as a move whose source is Trash and whose
  destination is not Trash).

Research notes (2026-11-25): community Proton MCPs lost mail by resolving a label name to any
mailbox (restrict to `Labels/`). Gluon's CLOSE expunges, so never send CLOSE. MCP tool
annotations are client hints only, and some clients never ask for confirmation, so every limit
is enforced on the server. Batch cap: 50 UIDs per call. (A daily budget was tried and removed at the owner's request.)

## imap.rs

Keep every existing guarantee (pinned STARTTLS, literal/size caps, response caps, tests). Add:

1. `Conn` tracks the selected mailbox: `None`, `Examined(name)` or `Selected(name)`, updated
   only after a tagged OK for EXAMINE/SELECT, and cleared after UNSELECT or a failed
   SELECT/EXAMINE.
2. `command_allowed(cmd, selected)`: the existing list, plus:
   - `SELECT`, `UNSELECT`, `CREATE`.
   - `UID STORE` with **only** `+FLAGS.SILENT`/`-FLAGS.SILENT` and a flag list drawn from
     `\Seen`, `\Flagged` and `\Deleted`. `\Deleted` is allowed only with `+FLAGS.SILENT` and only
     when the selected mailbox starts with `Labels/`.
   - `UID COPY` and `UID MOVE`.
   - `UID EXPUNGE`, only when the selected mailbox starts with `Labels/`.
   - `APPEND`, only to `"Drafts"`.

   Never allowed, with a test for each: plain `EXPUNGE`, `CLOSE` (it expunges), `DELETE`,
   `RENAME`, `STORE` without UID, `UID STORE` with `FLAGS` (a replace) or any other flag, and
   `SUBSCRIBE`. Matching is case-insensitive on the parsed command, never on a substring.
3. `Session` methods (all take UID slices; the server caps them at 50):
   - `select(mailbox)`
   - `uid_move(uids, dest) -> Vec<(u32,u32)>`: returns the (old, new) pairs from the COPYUID
     response code. It may arrive in a tagged OK or an untagged OK; empty if absent.
   - `uid_copy(uids, dest) -> Vec<(u32,u32)>`
   - `uid_store_flags(uids, add: bool, flags: &[Flag])`, where `Flag` is an enum
     `Seen | Flagged`. There is no `Deleted` variant here.
   - `remove_label(label_mailbox, uids)`: requires the name to start with `Labels/`. It SELECTs
     the label, runs `UID STORE +FLAGS.SILENT (\Deleted)` then `UID EXPUNGE` for exactly those
     UIDs, then `UNSELECT`. This is the only path that ever sends `\Deleted` or EXPUNGE.
   - `create(mailbox)`: the name must start with `Folders/` or `Labels/`, and the remaining
     segments must be non-empty, printable, with no `*` or `%`.
   - `append_draft(message: &[u8]) -> Option<u32>`:
     `APPEND "Drafts" (\Draft \Seen) {N}`, with synchronizing-literal handling: wait for `+`,
     send the bytes, then the CRLF. Cap the message at 2 MB. Return the UID from APPENDUID if
     present.
   - `fetch_attachment_source(uid, max_bytes)`: same as `fetch_message`, reused; no new code if
     not needed.
   - `Search` gains `message_id: Option<String>`, sent as `HEADER MESSAGE-ID "<quoted>"`.
4. Unit tests with the existing mock-stream pattern for every new method and every refusal.

## mime.rs + new draft.rs + new inflate.rs

1. `mime::attachment(raw: &[u8], index: usize) -> Option<AttachmentData>`, where
   `AttachmentData` is `{ filename, content_type, bytes }`, decoded from base64 or
   quoted-printable. The index matches the order of `parse(...).attachments`, so reuse the same
   walk; don't write a second, diverging one.
2. `mime::attachment_text(a: &AttachmentData, max_chars) -> Result<String, String>`:
   - `text/*`, `application/json`, `application/xml`, `text/csv` and `.txt`/`.csv`/`.md`/`.log`
     names: decode with charset handling (UTF-8, Latin-1, Windows-1252). Run HTML through the
     existing HTML-to-text.
   - `application/pdf`: best-effort text. Walk the objects, inflate FlateDecode streams with
     `inflate.rs`, and pull text from `Tj`, `TJ`, `'` and `"` operators, with `Td`/`T*`/`ET` as
     line breaks. Literal strings need escape handling; hex strings are allowed. Fonts with
     custom encodings or ToUnicode maps may give junk, which is acceptable. Hard caps: 50 MB of
     inflated output per document, 2,000 streams, linear time.
   - Anything else: `Err("binary attachment (<type>), text not available")`.
3. `inflate.rs`: an RFC 1950 (zlib wrapper) plus RFC 1951 DEFLATE decoder with stored, fixed
   and dynamic Huffman blocks. Enforce an output cap. A malformed stream gives an error, never a
   panic. Tests: known vectors (compress with Python's zlib, embed the bytes), every block type,
   truncated input, an oversized distance, and a zip-bomb cap.
4. `draft.rs`: `build_draft(from, to: &[String], cc: &[String], subject, body,
   in_reply_to: Option<&str>, references: Option<&str>, date, message_id) -> Result<Vec<u8>,
   String>`.
   - Reject CR/LF/NUL in every header input.
   - Addresses are `local@domain`, printable, no `<>,;"`.
   - Non-ASCII subjects get RFC 2047 B encoding, folded at 76 characters.
   - Body: `text/plain; charset=utf-8`, `Content-Transfer-Encoding: quoted-printable`.
   - Lines end in CRLF.
   - The caller supplies the date (RFC 5322 format) and the message ID; no clock or randomness
     inside this module.
   - Tests for injection attempts and for non-ASCII content.

`#![forbid(unsafe_code)]` still applies. No new crates.

## Integration: tools.rs, mcp.rs, main.rs, audit, compose, docs

New tools: `get_attachment`, `move_messages`, `trash_messages`, `add_label`, `remove_label`,
`mark_messages`, `create_mailbox` and `save_draft`.

- At most 50 UIDs per call.
- `move_messages` may target only `INBOX`, `Archive`, `Spam`, `Trash` and `Folders/*`. Labels go
  through `add_label`.
- Every change is written to the audit log as one JSON line in `/audit/audit.log`, a
  `./data/audit` volume owned by 65534, and also to stderr. Each line records: time, tool,
  arguments, the Message-ID and Subject of each message (fetched before the change), the COPYUID
  map, and the result.
- Write tools are marked `readOnlyHint:false`. Move, trash and remove_label are also
  `destructiveHint:true`.
