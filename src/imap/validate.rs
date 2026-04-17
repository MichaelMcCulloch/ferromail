use chrono::{DateTime, TimeZone, Utc};

use crate::types::{FerromailError, Result};

pub fn validate_uid(uid_str: &str) -> Result<u32> {
    uid_str
        .parse::<u32>()
        .map_err(|_| FerromailError::ImapError(format!("invalid UID: {uid_str}")))
}

pub fn validate_date(date_str: &str) -> DateTime<Utc> {
    let min = Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap();
    let max = Utc.with_ymd_and_hms(2100, 12, 31, 23, 59, 59).unwrap();

    let parsed = DateTime::parse_from_str(date_str, "%d-%b-%Y %H:%M:%S %z")
        .map(|dt| dt.with_timezone(&Utc))
        .or_else(|_| DateTime::parse_from_rfc2822(date_str).map(|dt| dt.with_timezone(&Utc)));

    match parsed {
        Ok(dt) if dt >= min && dt <= max => dt,
        _ => DateTime::UNIX_EPOCH,
    }
}

pub fn validate_tag(response_tag: &str, expected_tag: &str) -> Result<()> {
    if response_tag == expected_tag {
        return Ok(());
    }

    tracing::warn!(
        response_tag = response_tag,
        expected_tag = expected_tag,
        "IMAP response tag mismatch — discarding response"
    );

    Err(FerromailError::ImapError(format!(
        "IMAP response tag mismatch: expected {expected_tag}, got {response_tag}"
    )))
}

pub fn validate_literal_size(literal_size: u64, max_message_size: u64) -> Result<()> {
    if literal_size > max_message_size {
        return Err(FerromailError::ImapError(format!(
            "IMAP literal size {literal_size} exceeds limit {max_message_size}"
        )));
    }
    Ok(())
}

const MAX_UNSOLICITED: u64 = 1000;

pub struct UnsolicitedCounter {
    count: u64,
}

impl UnsolicitedCounter {
    pub fn new() -> Self {
        Self { count: 0 }
    }

    pub fn increment(&mut self) -> Result<()> {
        self.count += 1;
        if self.count > MAX_UNSOLICITED {
            return Err(FerromailError::ProtocolViolation(
                "Excessive unsolicited responses — possible server abuse".into(),
            ));
        }
        Ok(())
    }

    pub fn reset(&mut self) {
        self.count = 0;
    }

    pub fn count(&self) -> u64 {
        self.count
    }
}

impl Default for UnsolicitedCounter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_uid() {
        assert_eq!(validate_uid("12345").unwrap(), 12345);
        assert_eq!(validate_uid("1").unwrap(), 1);
        assert_eq!(validate_uid("4294967295").unwrap(), u32::MAX);
    }

    #[test]
    fn invalid_uid() {
        assert!(validate_uid("").is_err());
        assert!(validate_uid("abc").is_err());
        assert!(validate_uid("-1").is_err());
        assert!(validate_uid("4294967296").is_err());
        assert!(validate_uid("12 34").is_err());
    }

    #[test]
    fn valid_date_imap_format() {
        let dt = validate_date("17-Apr-2026 14:30:00 +0000");
        assert_ne!(dt, DateTime::UNIX_EPOCH);
        assert_eq!(dt.year(), 2026);
    }

    #[test]
    fn invalid_date_returns_epoch() {
        assert_eq!(validate_date("not-a-date"), DateTime::UNIX_EPOCH);
        assert_eq!(validate_date(""), DateTime::UNIX_EPOCH);
    }

    #[test]
    fn out_of_range_date_returns_epoch() {
        let dt = validate_date("01-Jan-1969 00:00:00 +0000");
        assert_eq!(dt, DateTime::UNIX_EPOCH);

        let dt = validate_date("01-Jan-2101 00:00:00 +0000");
        assert_eq!(dt, DateTime::UNIX_EPOCH);
    }

    #[test]
    fn tag_match() {
        assert!(validate_tag("A001", "A001").is_ok());
    }

    #[test]
    fn tag_mismatch() {
        assert!(validate_tag("A002", "A001").is_err());
    }

    #[test]
    fn literal_size_ok() {
        assert!(validate_literal_size(100, 26_214_400).is_ok());
    }

    #[test]
    fn literal_size_exceeds() {
        assert!(validate_literal_size(26_214_401, 26_214_400).is_err());
    }

    #[test]
    fn unsolicited_counter_under_limit() {
        let mut counter = UnsolicitedCounter::new();
        for _ in 0..1000 {
            assert!(counter.increment().is_ok());
        }
    }

    #[test]
    fn unsolicited_counter_over_limit() {
        let mut counter = UnsolicitedCounter::new();
        for _ in 0..1000 {
            counter.increment().unwrap();
        }
        assert!(counter.increment().is_err());
    }

    #[test]
    fn unsolicited_counter_reset() {
        let mut counter = UnsolicitedCounter::new();
        for _ in 0..500 {
            counter.increment().unwrap();
        }
        counter.reset();
        assert_eq!(counter.count(), 0);
        assert!(counter.increment().is_ok());
    }

    use chrono::Datelike;
}
