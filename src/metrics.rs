//! Prometheus-style metrics. Counters are incremented at call sites across
//! the crate and the serialized text-format output is exposed on
//! `/metrics` when the HTTP transport is enabled.
//!
//! Kept intentionally simple — a static `Metrics` struct with a few
//! high-signal counters. The full OTEL SDK is overkill here; a couple of
//! counters and a histogram cover the operational questions ferromail's
//! users actually ask (rate-limit triggers, login lockouts, gate denials).

use std::sync::OnceLock;

use prometheus::{
    Encoder, Histogram, HistogramOpts, IntCounter, IntCounterVec, Opts, Registry, TextEncoder,
};

pub struct Metrics {
    pub registry: Registry,
    pub tool_calls: IntCounterVec,
    pub gate_approvals: IntCounter,
    pub gate_denials: IntCounter,
    pub policy_denials: IntCounter,
    pub rate_limit_hits: IntCounterVec,
    pub login_lockouts: IntCounter,
    pub imap_connect_seconds: Histogram,
    pub oauth_refreshes: IntCounterVec,
    pub mta_sts_fetches: IntCounterVec,
}

impl Metrics {
    fn build() -> Self {
        let registry = Registry::new();

        let tool_calls = IntCounterVec::new(
            Opts::new("ferromail_tool_calls_total", "MCP tool invocations")
                .namespace("ferromail"),
            &["tool", "outcome"],
        )
        .expect("counter vec");

        let gate_approvals = IntCounter::with_opts(Opts::new(
            "ferromail_gate_approvals_total",
            "Confirmation-gate approvals (terminal/webhook/client)",
        ))
        .expect("counter");

        let gate_denials = IntCounter::with_opts(Opts::new(
            "ferromail_gate_denials_total",
            "Confirmation-gate denials",
        ))
        .expect("counter");

        let policy_denials = IntCounter::with_opts(Opts::new(
            "ferromail_policy_denials_total",
            "Cedar policy engine denials (pre-gate)",
        ))
        .expect("counter");

        let rate_limit_hits = IntCounterVec::new(
            Opts::new(
                "ferromail_rate_limit_hits_total",
                "Rate-limit triggers per (account, operation)",
            ),
            &["account", "operation"],
        )
        .expect("counter vec");

        let login_lockouts = IntCounter::with_opts(Opts::new(
            "ferromail_login_lockouts_total",
            "Login-gate lockouts after consecutive auth failures",
        ))
        .expect("counter");

        let imap_connect_seconds = Histogram::with_opts(
            HistogramOpts::new(
                "ferromail_imap_connect_seconds",
                "Time from TCP connect to authenticated IMAP session",
            )
            .buckets(vec![0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
        )
        .expect("histogram");

        let oauth_refreshes = IntCounterVec::new(
            Opts::new(
                "ferromail_oauth_refreshes_total",
                "OAuth2 access-token refresh outcomes",
            ),
            &["provider", "outcome"],
        )
        .expect("counter vec");

        let mta_sts_fetches = IntCounterVec::new(
            Opts::new(
                "ferromail_mta_sts_fetches_total",
                "MTA-STS policy fetch outcomes by recipient domain mode",
            ),
            &["outcome"],
        )
        .expect("counter vec");

        registry.register(Box::new(tool_calls.clone())).unwrap();
        registry.register(Box::new(gate_approvals.clone())).unwrap();
        registry.register(Box::new(gate_denials.clone())).unwrap();
        registry.register(Box::new(policy_denials.clone())).unwrap();
        registry.register(Box::new(rate_limit_hits.clone())).unwrap();
        registry.register(Box::new(login_lockouts.clone())).unwrap();
        registry
            .register(Box::new(imap_connect_seconds.clone()))
            .unwrap();
        registry.register(Box::new(oauth_refreshes.clone())).unwrap();
        registry.register(Box::new(mta_sts_fetches.clone())).unwrap();

        Self {
            registry,
            tool_calls,
            gate_approvals,
            gate_denials,
            policy_denials,
            rate_limit_hits,
            login_lockouts,
            imap_connect_seconds,
            oauth_refreshes,
            mta_sts_fetches,
        }
    }

    /// Render in the standard Prometheus text exposition format.
    pub fn render(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let encoder = TextEncoder::new();
        let families = self.registry.gather();
        if encoder.encode(&families, &mut buf).is_err() {
            buf.clear();
        }
        buf
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::build()
    }
}

static METRICS: OnceLock<Metrics> = OnceLock::new();

pub fn global() -> &'static Metrics {
    METRICS.get_or_init(Metrics::build)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_increment_and_render() {
        let m = Metrics::build();
        m.tool_calls.with_label_values(&["send_email", "ok"]).inc();
        m.gate_approvals.inc();
        m.policy_denials.inc();
        m.rate_limit_hits
            .with_label_values(&["work", "send"])
            .inc();

        let text = m.render();
        let s = String::from_utf8(text).unwrap();
        assert!(s.contains("ferromail_tool_calls_total"));
        assert!(s.contains("ferromail_gate_approvals_total 1"));
        assert!(s.contains("ferromail_policy_denials_total 1"));
    }

    #[test]
    fn global_is_singleton() {
        let a = global() as *const _;
        let b = global() as *const _;
        assert_eq!(a, b);
    }
}
