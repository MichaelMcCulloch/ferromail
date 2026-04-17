use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::types::{FerromailError, Result};

/// Tracks consecutive IMAP LOGIN failures per account and enforces two
/// policies from SPEC.md §14.3:
/// - Exponential backoff between retries: 1s, 2s, 4s, 8s, capped at 60s.
/// - After `MAX_CONSECUTIVE_FAILURES` consecutive failures, the gate refuses
///   further attempts and signals the caller to disable the account.
pub const MAX_CONSECUTIVE_FAILURES: u32 = 5;

#[derive(Debug, Clone, Copy, Default)]
struct AttemptState {
    consecutive_failures: u32,
    last_failure_at: Option<Instant>,
}

#[derive(Default)]
pub struct LoginGate {
    per_account: Mutex<HashMap<String, AttemptState>>,
}

/// Result of a `check` call: either OK to attempt, or refuse with a reason.
#[derive(Debug)]
pub enum LoginCheck {
    Ok,
    /// Account is locked out — caller must disable it.
    LockedOut,
    /// Too soon since last failure; wait and retry.
    BackoffActive {
        retry_after_seconds: u64,
    },
}

impl LoginGate {
    pub fn new() -> Self {
        Self::default()
    }

    /// Is this account allowed to attempt a login right now?
    pub fn check(&self, account: &str) -> LoginCheck {
        let map = self.per_account.lock().expect("login gate mutex poisoned");
        let state = map.get(account).copied().unwrap_or_default();

        if state.consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
            return LoginCheck::LockedOut;
        }

        if let Some(last) = state.last_failure_at {
            let wait = backoff_for(state.consecutive_failures);
            let elapsed = last.elapsed();
            if elapsed < wait {
                let remaining = wait - elapsed;
                return LoginCheck::BackoffActive {
                    retry_after_seconds: remaining.as_secs().max(1),
                };
            }
        }

        LoginCheck::Ok
    }

    /// Record a successful login. Clears the failure counter.
    pub fn record_success(&self, account: &str) {
        let mut map = self.per_account.lock().expect("login gate mutex poisoned");
        map.remove(account);
    }

    /// Record a failure. Returns true if this failure has now tripped the
    /// lockout threshold (caller should disable the account).
    pub fn record_failure(&self, account: &str) -> bool {
        let mut map = self.per_account.lock().expect("login gate mutex poisoned");
        let entry = map.entry(account.to_string()).or_default();
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        entry.last_failure_at = Some(Instant::now());
        entry.consecutive_failures >= MAX_CONSECUTIVE_FAILURES
    }

    /// Convert a LoginCheck into a Result.
    pub fn check_err(&self, account: &str) -> Result<()> {
        match self.check(account) {
            LoginCheck::Ok => Ok(()),
            LoginCheck::LockedOut => Err(FerromailError::ConfigError(format!(
                "Account '{account}' is locked out after {MAX_CONSECUTIVE_FAILURES} consecutive \
                 LOGIN failures. Re-enable with `ferromail account enable {account}`."
            ))),
            LoginCheck::BackoffActive {
                retry_after_seconds,
            } => Err(FerromailError::RateLimitExceeded {
                retry_after_seconds,
            }),
        }
    }
}

fn backoff_for(failures: u32) -> Duration {
    // 0 failures: no backoff (handled by caller — check is the last-failure path).
    // 1 → 1s, 2 → 2s, 3 → 4s, 4 → 8s, 5+ → 60s (cap).
    let secs = match failures {
        0 | 1 => 1,
        2 => 2,
        3 => 4,
        4 => 8,
        _ => 60,
    };
    Duration::from_secs(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_account_is_ok() {
        let gate = LoginGate::new();
        assert!(matches!(gate.check("acc"), LoginCheck::Ok));
    }

    #[test]
    fn success_clears_failures() {
        let gate = LoginGate::new();
        gate.record_failure("acc");
        gate.record_failure("acc");
        gate.record_success("acc");
        assert!(matches!(gate.check("acc"), LoginCheck::Ok));
    }

    #[test]
    fn lockout_after_five() {
        let gate = LoginGate::new();
        for _ in 0..4 {
            let tripped = gate.record_failure("acc");
            assert!(!tripped);
        }
        let tripped = gate.record_failure("acc");
        assert!(tripped, "5th failure should trip lockout");
        assert!(matches!(gate.check("acc"), LoginCheck::LockedOut));
    }

    #[test]
    fn backoff_after_first_failure() {
        let gate = LoginGate::new();
        gate.record_failure("acc");
        match gate.check("acc") {
            LoginCheck::BackoffActive {
                retry_after_seconds,
            } => {
                assert!(retry_after_seconds >= 1);
            }
            other => panic!("expected backoff, got {other:?}"),
        }
    }

    #[test]
    fn backoff_schedule_escalates() {
        assert_eq!(backoff_for(1), Duration::from_secs(1));
        assert_eq!(backoff_for(2), Duration::from_secs(2));
        assert_eq!(backoff_for(3), Duration::from_secs(4));
        assert_eq!(backoff_for(4), Duration::from_secs(8));
        assert_eq!(backoff_for(10), Duration::from_secs(60));
    }

    #[test]
    fn check_err_returns_appropriate_error() {
        let gate = LoginGate::new();
        assert!(gate.check_err("acc").is_ok());

        gate.record_failure("acc");
        let err = gate.check_err("acc").unwrap_err();
        match err {
            FerromailError::RateLimitExceeded { .. } => {}
            other => panic!("expected RateLimitExceeded, got {other:?}"),
        }
    }
}
