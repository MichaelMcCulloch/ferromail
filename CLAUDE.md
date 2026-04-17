# ferromail Development Guidelines

Auto-generated from all feature plans. Last updated: 2026-04-17

## Active Technologies

- Rust 1.92, Edition 2024 + tokio (async runtime), async-imap (IMAP client), lettre (SMTP client/message builder), rustls (TLS), clap (CLI), serde + toml (config), tracing (logging), secrecy + zeroize (credential hygiene), ammonia (HTML strip), encoding_rs (charset), keyring (OS credential store), age (encrypted file store) (001-hardened-mcp-email)

## Project Structure

```text
src/
tests/
```

## Commands

cargo test [ONLY COMMANDS FOR ACTIVE TECHNOLOGIES][ONLY COMMANDS FOR ACTIVE TECHNOLOGIES] cargo clippy

## Code Style

Rust 1.92, Edition 2024: Follow standard conventions

## Recent Changes

- 001-hardened-mcp-email: Added Rust 1.92, Edition 2024 + tokio (async runtime), async-imap (IMAP client), lettre (SMTP client/message builder), rustls (TLS), clap (CLI), serde + toml (config), tracing (logging), secrecy + zeroize (credential hygiene), ammonia (HTML strip), encoding_rs (charset), keyring (OS credential store), age (encrypted file store)

<!-- MANUAL ADDITIONS START -->
<!-- MANUAL ADDITIONS END -->
