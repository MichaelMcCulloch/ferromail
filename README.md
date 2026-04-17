# ferromail

**A hardened IMAP/SMTP MCP server in Rust.**

ferromail is a [Model Context Protocol](https://modelcontextprotocol.io) server
that lets an LLM agent read, send, reply to, and delete email on behalf of a
human — with strong defenses against prompt injection, malicious mail servers,
and a compromised agent.

Status: **v0.1 complete.** stdio + SSE/HTTP transports both working. 160 tests pass (109 unit + 51 integration/adversarial). Zero clippy warnings.

## What makes it different

ferromail assumes three adversaries simultaneously, and defends against each
independently:

| Adversary | Defense |
| --- | --- |
| **Malicious email sender** trying to prompt-inject the agent | Every field of every fetched message lives in its own `<ferromail:field name="...">` tag inside a `<ferromail:untrusted>` envelope; tag closers are escaped post-sanitize. HTML stripped to plaintext via `ammonia`. Bidi overrides, UTF-7, invisible chars, and control characters stripped. **DKIM / SPF / DMARC / ARC** authentication results (both upstream `Authentication-Results` and local DKIM re-verification via `mail-auth`) surfaced as `<ferromail:auth trusted="...">`. **Sender-spoof heuristics** (display-name embedding a different `@addr`, Cyrillic homograph domains, invisible chars in the domain) surfaced as `<ferromail:spoof suspicious="...">`. |
| **Malicious/compromised IMAP or SMTP server** | rustls with the **aws-lc-rs** provider → **X25519MLKEM768 post-quantum hybrid** KEX enabled by default. Platform verifier, min TLS 1.2. STARTTLS buffer-discard on upgrade. PREAUTH on plaintext is rejected. Server referrals are logged but never followed. Unsolicited responses are rate-limited. |
| **Jailbroken agent** trying to exfiltrate or destroy | **Cedar policy engine** evaluates every write/destructive tool call against `policy.cedar` before the confirmation gate — rejected calls never prompt the user. Every remaining call is gated (MCP client UI, terminal y/N, or webhook). Destructive ops add a 3-second cooldown. Rate limits: 20 sends/hour, 100 deletes/hour per account. Path sandboxing with canonicalize + prefix assertion on every file write. **MTA-STS policy fetch** for each recipient domain is logged. |
| **Host-level compromise** of the MCP process | **Landlock** (Linux ≥ 5.13) restricts FS access to config, downloads, and send-allow dirs. **seccomp-bpf** deny-list kills the usual post-exploit syscall surface (ptrace, bpf, kexec, module load, keyctl, namespace surgery, etc.) before tokio spawns workers, so the filter inherits on clone. `prctl(PR_SET_NO_NEW_PRIVS, 1)` + `PR_SET_DUMPABLE=0` + `RLIMIT_CORE=0`. Ship with the provided hardened `systemd/ferromail.service` for a second layer (NoNewPrivs, ProtectSystem=strict, SystemCallFilter, MemoryDenyWriteExecute, etc). |
| **Credential compromise** via stolen password | **OAuth2 / XOAUTH2 / OAUTHBEARER** for Gmail and Microsoft 365 (device-code flow, access+refresh tokens in the OS keyring or age-file). App passwords remain supported for providers that still need them. Secrets wrapped in `secrecy::SecretString`, zeroized on drop. |

All of this is defense in depth: the LLM system prompt is a recommendation,
the confirmation gate is the hard boundary.

## MCP tools exposed

| Tool | Tier | Description |
| --- | --- | --- |
| `list_accounts` | read | Masked account list (no credentials) |
| `list_emails` | read | Paginated metadata with filters (date, sender, subject, flags) |
| `get_email_content` | read | Sanitized body + headers + attachment metadata, wrapped in isolation markers |
| `send_email` | write | Requires confirmation |
| `reply_to_email` | write | Requires confirmation; preserves `In-Reply-To` / `References` |
| `delete_emails` | destructive | Requires confirmation + 3s cooldown; UID STORE + EXPUNGE |
| `download_attachment` | destructive | Requires confirmation; writes to sandbox only |

See `src/transport/stdio.rs` for the JSON-Schema input definitions and
`specs/001-hardened-mcp-email/contracts/mcp-tools.md` for the full contract.

## Install

```bash
git clone <this repo>
cd ferromail
cargo build --release
# Binary at ./target/release/ferromail
```

**Requires:** Rust 1.92 (Edition 2024), Linux or macOS.

## First-time setup

```bash
# Create config directory (~/.config/ferromail) with 0o700 permissions
ferromail init

# Add an email account interactively. Passwords are prompted via rpassword
# and stored in the OS keyring (default) or an age-encrypted file.
ferromail account add work

# Verify IMAP and SMTP connectivity
ferromail account test work
```

Config lives at `~/.config/ferromail/config.toml` (override with
`$FERROMAIL_CONFIG`). ferromail refuses to start if the file or directory has
group/world bits set and prints the exact `chmod` command to fix it.

## Run as MCP server

**stdio (recommended — Claude Desktop, most MCP clients):**

```bash
ferromail serve --transport stdio
```

Wire it into Claude Desktop by adding this to
`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or
the equivalent on your platform:

```json
{
  "mcpServers": {
    "ferromail": {
      "command": "/absolute/path/to/ferromail",
      "args": ["serve", "--transport", "stdio"]
    }
  }
}
```

Then include the contents of [`system-prompt-fragment.md`](./system-prompt-fragment.md)
in your LLM system prompt so the agent treats email content as data, not
instructions.

**SSE/HTTP (stubbed in v0.1):**

```bash
# Bearer token is generated, written to config dir (0o600), and printed to stderr.
# Binding to non-loopback requires the explicit --i-understand-network-exposure flag.
ferromail serve --transport sse --host 127.0.0.1 --port 9557
```

### Confirmation channel

The `[confirmation].channel` setting in `config.toml` picks how write/destructive
operations get approved:

| Channel | Behavior |
| --- | --- |
| `"none"` *(default)* | No ferromail-level prompt. The MCP client's per-tool approval UI is the trust boundary. Destructive cooldown still applies. |
| `"terminal"` | y/N prompt on stderr, reading from `/dev/tty`. Use when running ferromail as a standalone CLI in a terminal. Fails if stderr isn't a TTY. |
| `"webhook"` | POST the summary to `webhook_url`; proceed only on `{"approve": true}`. Use for headless deployments with a local approval UI or remote approver. |

## Configuration

A minimal `config.toml`:

```toml
[[account]]
name = "work"
email_address = "me@example.com"
full_name = "My Name"
enabled = true

[account.imap]
host = "imap.example.com"
port = 993
tls = "required"          # "required" | "starttls-unsafe" | "none"
verify_certs = true
min_tls_version = "1.2"   # "1.2" | "1.3"

[account.smtp]
host = "smtp.example.com"
port = 465
tls = "required"
verify_certs = true
min_tls_version = "1.2"
save_to_sent = true
sent_folder = ""          # "" auto-detects
```

Defaults for rate limits, timeouts, MIME caps, and sandbox paths all live
under `[limits]`, `[timeouts]`, `[rate_limits]`, `[attachments]`,
`[confirmation]`, `[logging]`, and `[credentials]`. See
`src/config.rs` for the full schema and defaults.

### Credential storage

| Backend | How |
| --- | --- |
| `keyring` (default) | OS keyring — Secret Service on Linux, Keychain on macOS |
| `age-file` | age-encrypted file at `~/.config/ferromail/credentials.age`, passphrase prompted on each access |

Override via the `[credentials]` section of config. Passwords are wrapped in
`secrecy::SecretString` and zeroized on drop. Core dumps are disabled via
`prctl(PR_SET_DUMPABLE, 0)` and `RLIMIT_CORE = 0` at process start.

## Testing

```bash
# Full test suite: unit + adversarial
cargo test -- --test-threads=1

# Just the adversarial suite
cargo test --test 'adversarial_*'
```

Current coverage: **140 tests passing** (101 unit + 39 adversarial).

The adversarial suite drives the security contracts directly:

- `adversarial_path_traversal.rs` — `../`, absolute paths, Windows separators,
  URL-encoded, null bytes, Unicode fullwidth, bidi overrides
- `adversarial_smtp_injection.rs` — CRLF in addresses / subjects /
  Message-ID / References; DATA-terminator handling; line-ending normalization
- `adversarial_prompt_injection.rs` — `</ferromail:untrusted>` in body,
  header, filename, attachment metadata; UTF-7 encoded variants; HTML injection
- `adversarial_mime_bombs.rs` — deeply nested multiparts, thousand-part
  messages, zero-byte filenames, RTL override filenames, malformed boundaries

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ MCP Transport (stdio JSON-RPC, SSE/HTTP stubbed)            │
├─────────────────────────────────────────────────────────────┤
│ Tool Layer           read · write · destructive             │
├─────────────────────────────────────────────────────────────┤
│ Confirmation Gate    terminal prompt + 3s cooldown          │
├─────────────────────────────────────────────────────────────┤
│ Sanitization         body · header · filename · outbound    │
│                      isolation markers                       │
├─────────────────────────────────────────────────────────────┤
│ Protocol             rustls · async-imap · lettre           │
├─────────────────────────────────────────────────────────────┤
│ Credential Store     keyring · age-encrypted file           │
└─────────────────────────────────────────────────────────────┘
```

- `src/config.rs` — config schema, permission checks, env-var override
- `src/credential.rs` — keyring / age backends with `SecretString`
- `src/gate.rs` — terminal confirmation with `/dev/tty` isolation from MCP stdio
- `src/sanitize/` — 10-stage body pipeline, 8-stage header pipeline, 10-stage filename pipeline
- `src/imap/` — rustls-backed IMAP client with greeting verification and STARTTLS buffer discard
- `src/smtp.rs` — lettre wrapper with outbound CRLF validation
- `src/sandbox.rs` — canonicalize + prefix-assert download paths
- `src/mime_parse.rs` — mail-parser with depth/parts/size caps
- `src/transport/stdio.rs` — JSON-RPC MCP transport
- `src/email_auth.rs` — DKIM / SPF / DMARC / ARC verification via `mail-auth`
- `src/sanitize/spoof.rs` — From-header spoof heuristics (display-name, homographs)
- `src/mta_sts.rs` — RFC 8461 policy fetch + parse + cache
- `src/os_sandbox.rs` — Landlock + seccomp-bpf (Linux only)
- `src/oauth.rs` — OAuth 2.0 device flow, refresh, XOAUTH2 SASL
- `src/policy.rs` — Cedar tool-call policy engine
- `src/metrics.rs` — Prometheus-format metrics at `/metrics`
- `systemd/ferromail.service` — hardened unit for systemd deployments
- `deny.toml` — cargo-deny supply-chain rules
- `.github/workflows/ci.yml` — fmt, clippy, test, audit, deny, semgrep, SBOM

See [`SPEC.md`](./SPEC.md) for the full design specification and
[`specs/001-hardened-mcp-email/`](./specs/001-hardened-mcp-email) for plan,
research, data model, and contracts.

## Limitations (v0.1)

- Search is IMAP-server-side only. No local index.
- Single confirmation channel per server process (terminal OR webhook, chosen
  at startup). Runtime channel switching is v0.2.

## License

TBD.
