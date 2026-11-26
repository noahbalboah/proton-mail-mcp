# proton-mail-mcp

An MCP server that gives an AI agent access to a Proton Mail mailbox through
[Proton Mail Bridge](https://proton.me/mail/bridge). It is reachable only over your
[Tailscale](https://tailscale.com) tailnet. The agent can read mail and attachments, organize it
(move, trash, labels, read/star, new folders) and save drafts. It cannot send mail, and it cannot
permanently delete anything.

```
agent (tailnet) ──443──> ts-mail (tailscale serve, HTTPS)
  ──ts-link──> mail-mcp :8080 (this server, bearer token)
  ──mail-internal──> bridge :11143 (IMAP STARTTLS, pinned cert) ──> Proton
```

- **`server/`**: the MCP server, written in Rust. Its only third-party dependencies are `rustls`
  and `ring`. The IMAP client, HTTP server, JSON, MIME, DEFLATE (for PDF text) and draft builder
  are all in this repo. It runs as a static binary on a `scratch` image of about 3 MB, as uid
  65534, with a read-only filesystem and no capabilities. It has no route to the internet.
- **`bridge/`**: Proton Mail Bridge built from Proton's signed `.deb`, with the SHA-256 pinned. It
  runs Bridge's core binary, not Proton's launcher, so a downloaded update never runs. It exposes
  IMAP only, never SMTP.
- **`ts/serve.json`**: the `tailscale serve` config for the sidecar.
- **`docs/`**: the design contracts the code was built against.

## Tools

| Tool | What it does |
|------|--------------|
| `list_mailboxes` | Folders (`Folders/...`) and labels (`Labels/...`) |
| `list_messages` | Newest first, with search by sender, subject, text, date or unread; paged |
| `get_message` | Headers, numbered attachments and the text body (HTML converted to text) |
| `get_attachment` | Text of one attachment: text, CSV, JSON, XML, HTML, or PDF (best effort) |
| `move_messages` | To INBOX, Archive, Spam, Trash or a `Folders/` folder |
| `trash_messages` | Move to Trash, recoverable in Proton for 30 days |
| `add_label` / `remove_label` | Labels on and off; the messages themselves are untouched |
| `mark_messages` | Read/unread, starred/unstarred |
| `create_mailbox` | New folder or label |
| `save_draft` | Plain-text draft in Drafts, for you to review and send. Never sent from here. |

Reading never marks anything as read: it uses `EXAMINE` and `BODY.PEEK`.

### Sender check

Every message gets one of four ratings: `PASS`, `CAUTION`, `DANGER` or `UNVERIFIED`. The rating
is shown in `list_messages`, and `get_message` gives the reasons.

- **Inputs.** It is built from the SPF, DKIM and DMARC results Proton's servers recorded, and
  from Proton's spam verdict, which marks phishing.
- **Forged results.** Only results in the positions Proton writes them are trusted: above the
  first `Received` header, and the last spam-verdict line. A message that carries its own fake
  "Proton" results is rated `DANGER`.
- **Other checks.** It also flags:
  - a Reply-To on a different domain from From;
  - lookalike display names and domains (`PayPal` sent from `paypa1.com`, punycode, mixed
    scripts);
  - links whose visible text names a different domain from the one they open, or that point to
    a raw IP address, `javascript:` or `data:`.
- **Drafts.** `save_draft` warns when the message being answered failed the check.
- **Limits.** No network lookups. Attachments are not scanned for malware. A phishing message
  sent from a real, properly authenticated account can still pass.

## Safety model

Assume email content is hostile: a message can contain text written to steer the agent. MCP tool
annotations are only hints, and some clients never ask before running a tool, so the limits below
are enforced by the server:

- **No permanent deletion.** The IMAP layer refuses `EXPUNGE`, `CLOSE` (which expunges),
  `DELETE`, `RENAME` and `STORE FLAGS`. `\Deleted` and `UID EXPUNGE` are only allowed inside a
  `Labels/` mailbox, where Bridge treats them as "remove this label". Every refusal has a test.
- **Trash guard.** Bridge can permanently delete a message that is moved to Trash a second time,
  for example when it sat in both Inbox and Sent. `trash_messages` looks each Message-ID up in
  Trash first and skips any already there.
- **Real folders only.** Move and trash sources must be real folders, never All Mail, Starred or
  a label. A label name always resolves to `Labels/<name>`, never to another mailbox.
- **Limits on how much can change.** At most 50 messages per call. Moves, trash and label
  removals share a budget of 300 messages per rolling 24 hours, rebuilt from the audit log after a
  restart.
- **Audit log.** Every change writes an intent line before anything is sent to Bridge, then a
  done or failed line with Message-IDs, subjects and the old→new UID map, so it can be undone.
  If the log can't be written, the change doesn't run.
- **Untrusted-data fences.** Email text is returned inside
  `<untrusted-email-data id="random">…</untrusted-email-data id="random">`, so a message can't
  fake the end of its own fence.
- **Transport.** The server is reachable only on the tailnet, needs a bearer token (compared in
  constant time) and refuses any request carrying an `Origin` header. Bridge's TLS certificate is
  pinned by SHA-256.

## Deploy

Needs Docker with Compose on an x86-64 host, a Proton plan that includes Bridge (paid), and a
tailnet.

1. **Tailnet policy.** Tag the agent's device (`tag:agent` here) and the server (`tag:mail-mcp`),
   then grant only port 443:
   ```hujson
   "tagOwners": { "tag:agent": ["autogroup:admin"], "tag:mail-mcp": ["autogroup:admin"] },
   "grants": [ { "src": ["tag:agent"], "dst": ["tag:mail-mcp"], "ip": ["tcp:443"] } ],
   "tests": [ { "src": "tag:agent", "accept": ["tag:mail-mcp:443"], "deny": ["tag:mail-mcp:22"] } ],
   ```
   If your policy still has the default allow-all rule, an untagged agent device can reach
   everything. Tag it.
2. **Auth key.** In the Tailscale admin console, go to Settings → Keys and create a single-use,
   pre-approved key tagged `tag:mail-mcp`. Put it in `ts.env` (see `ts.env.example`).
3. **Folders.**
   ```
   mkdir -p data/bridge data/tailscale data/audit secrets
   sudo chown 1001:1001 data/bridge && sudo chown root:root data/tailscale
   sudo chown 65534:65534 data/audit && sudo chmod 700 data/*
   touch ts.env mail-mcp.env && chmod 600 ts.env mail-mcp.env
   docker compose build
   ```
4. **Bridge login** (one time, interactive):
   ```
   docker compose run --rm -it bridge login
   ```
   In the Bridge shell, run `login` (Proton username, password, 2FA), then `info` for the IMAP
   username and the Bridge password. Run `telemetry disable` and `updates autoupdates disable`,
   then `exit`.
5. **Start Bridge and pin its certificate.**
   ```
   docker compose up -d bridge
   docker compose run --rm mail-mcp fingerprint
   ```
6. **Settings and secrets.** Put `IMAP_USER` and `IMAP_CERT_SHA256` in `mail-mcp.env` (see
   `mail-mcp.env.example`). The secrets are files, so `docker inspect` never shows them:
   ```
   openssl rand -hex 32 | sudo tee secrets/mcp_token >/dev/null    # the agent's bearer token
   sudo sh -c 'cat > secrets/imap_password'                        # the Bridge password, then Ctrl-D
   sudo chown 65534:65534 secrets secrets/* && sudo chmod 400 secrets/* && sudo chmod 500 secrets
   ```
7. `docker compose up -d`
8. **Point the agent at it**: `https://mail-mcp.<your-tailnet>.ts.net/mcp` with the header
   `Authorization: Bearer <token>`.

## Operate

- **Review changes:** `sudo tail data/audit/audit.log` (one JSON object per line).
- **Cut access at once:** `docker compose stop ts-mail`.
- **Rotate the token:** write a new `secrets/mcp_token`, run
  `docker compose restart mail-mcp`, then update the agent.
- **Upgrade Bridge:** check the new `.deb` against Proton's signing key
  (`D51E 64D3 E63E DC3E EF78 64CE E2C7 5D68 E623 4B07`), then update the version and SHA-256 in
  `bridge/Dockerfile`. If the certificate changes, repeat step 5.
- **`data/bridge` holds the Bridge vault and an unprotected gpg key**, so anyone who can read it
  can read the mailbox. Keep it out of unencrypted backups.

## Known limits

- **Search runs inside Bridge.** In testing, a multi-word subject search found nothing for a
  subject Bridge stored RFC 2047-encoded (one containing an emoji), while a single word from it
  matched. Plain subjects search normally.
- **Drafts don't thread as replies.** Bridge drops In-Reply-To and References on APPEND, so a
  draft saved with `reply_to_uid` won't thread in Proton.
- **Mailbox names must be ASCII.** Folder and label names outside printable ASCII are refused,
  because modified UTF-7 isn't implemented.

## Develop

```
cd server && cargo test && cargo clippy --all-targets -- -D warnings
```

Server settings (environment): `MCP_TOKEN[_FILE]`, `IMAP_USER`, `IMAP_PASSWORD[_FILE]`,
`IMAP_CERT_SHA256`, `IMAP_HOST` (default `bridge`), `IMAP_PORT` (default `11143`), `LISTEN_ADDR`
(default `0.0.0.0:8080`), `AUDIT_LOG` (default `/audit/audit.log`), `DRAFT_FROM` (default
`IMAP_USER`).

Not affiliated with Proton AG or Tailscale Inc.

## License

MIT, see [LICENSE](LICENSE).
