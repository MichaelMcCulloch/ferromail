use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::types::{FerromailError, Result};

const WINDOW: Duration = Duration::from_secs(3600);

pub struct RateLimiter {
    windows: HashMap<(String, String), Vec<Instant>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            windows: HashMap::new(),
        }
    }

    pub fn check(&mut self, account: &str, operation: &str, max_per_hour: u32) -> Result<()> {
        let now = Instant::now();
        let key = (account.to_owned(), operation.to_owned());
        let timestamps = self.windows.entry(key).or_default();

        timestamps.retain(|t| now.duration_since(*t) < WINDOW);

        if timestamps.len() >= max_per_hour as usize {
            let oldest = timestamps
                .first()
                .expect("non-empty after len >= max check");
            let age = now.duration_since(*oldest);
            let retry_after = WINDOW.saturating_sub(age).as_secs().max(1);
            return Err(FerromailError::RateLimitExceeded {
                retry_after_seconds: retry_after,
            });
        }

        timestamps.push(now);
        Ok(())
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}
