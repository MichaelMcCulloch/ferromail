//! Linux-only in-process OS sandboxing.
//!
//! Two layers stacked on top of one another:
//!
//! 1. **Landlock** (Linux ≥ 5.13) restricts the filesystem view of the
//!    process and its descendants to the directories ferromail legitimately
//!    needs: config (read+write for token refresh and audit log), download
//!    dir (write), and any send_allow_dirs (read, for attaching outgoing
//!    files). TLS trust store, resolver, and /proc for libc are allowed
//!    read-only.
//!
//! 2. **seccomp-bpf** installs a syscall filter (deny-list) that kills a
//!    handful of syscalls no MCP email server ever needs (ptrace, bpf,
//!    kexec_load, process_vm_read/writev, keyctl, module loading,
//!    namespace/mount surgery). Unknown syscalls default to Allow so the
//!    filter is resilient to kernel and glibc updates — the hard
//!    access-control work is done by Landlock.
//!
//! Both filters are applied from the main thread before tokio spawns any
//! worker threads (the Linux task_struct lands via `clone()`, which
//! inherits both Landlock domains and seccomp filters). `apply_filter_all_threads`
//! synchronises seccomp across any threads that did start early.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use landlock::{
    ABI, Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
    RulesetStatus,
};
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch};

use crate::types::{FerromailError, Result};

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub config_dir: PathBuf,
    pub download_dir: PathBuf,
    pub send_allow_dirs: Vec<PathBuf>,
}

/// Apply both Landlock and seccomp-bpf. Safe to call once, before tokio's
/// runtime workers pick up work.
pub fn apply(config: &SandboxConfig) -> Result<()> {
    set_no_new_privs()?;
    apply_seccomp()?;
    apply_landlock(config)?;
    Ok(())
}

fn set_no_new_privs() -> Result<()> {
    // seccompiler::apply_filter_all_threads refuses to install a filter unless
    // NO_NEW_PRIVS is set (the kernel-level contract). It's also a
    // prerequisite for Landlock without CAP_SYS_ADMIN.
    #[allow(unsafe_code)]
    // SAFETY: prctl with PR_SET_NO_NEW_PRIVS has no memory semantics; return
    // value is ignored as failure here just means the later seccomp call will
    // return a clearer error.
    unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    }
    Ok(())
}

fn apply_landlock(config: &SandboxConfig) -> Result<()> {
    let abi = ABI::V4;
    let read = AccessFs::from_read(abi);
    let write = AccessFs::from_write(abi);
    // Compose read+write via bitflags.
    let rw = read | write;

    // Collect unique read-only roots. Missing paths are silently skipped —
    // Landlock refuses rules on nonexistent paths, and we don't want the
    // sandbox to crash because e.g. /etc/ssl is in a non-standard place.
    let mut ro_paths: Vec<PathBuf> = Vec::new();
    ro_paths.extend(config.send_allow_dirs.iter().cloned());
    ro_paths.extend([
        PathBuf::from("/etc/ssl"),
        PathBuf::from("/etc/pki"),
        PathBuf::from("/etc/ca-certificates"),
        PathBuf::from("/etc/resolv.conf"),
        PathBuf::from("/etc/hosts"),
        PathBuf::from("/etc/nsswitch.conf"),
        PathBuf::from("/etc/gai.conf"),
        PathBuf::from("/etc/localtime"),
        PathBuf::from("/usr/share/zoneinfo"),
        PathBuf::from("/usr/lib/ssl"),
        PathBuf::from("/usr/share/ca-certificates"),
        PathBuf::from("/proc/self"),
        PathBuf::from("/sys/devices/system/cpu"),
    ]);

    let rw_paths = vec![config.config_dir.clone(), config.download_dir.clone()];

    let mut created = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(landlock_err)?
        .create()
        .map_err(landlock_err)?;

    for p in &ro_paths {
        if let Some(fd) = open_path(p) {
            created = created
                .add_rule(PathBeneath::new(fd, read))
                .map_err(landlock_err)?;
        }
    }
    for p in &rw_paths {
        if let Some(fd) = open_path(p) {
            created = created
                .add_rule(PathBeneath::new(fd, rw))
                .map_err(landlock_err)?;
        }
    }

    let status = created.restrict_self().map_err(landlock_err)?;
    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            tracing::info!(target: "sandbox", "Landlock: fully enforced");
        }
        RulesetStatus::PartiallyEnforced => {
            tracing::warn!(target: "sandbox", "Landlock: partially enforced; kernel ABI older than V4");
        }
        RulesetStatus::NotEnforced => {
            tracing::warn!(target: "sandbox", "Landlock: not enforced; kernel lacks LSM support");
        }
    }
    Ok(())
}

fn open_path(p: &Path) -> Option<PathFd> {
    if !p.exists() {
        return None;
    }
    PathFd::new(p.as_os_str()).ok()
}

fn apply_seccomp() -> Result<()> {
    let arch = match std::env::consts::ARCH {
        "x86_64" => TargetArch::x86_64,
        "aarch64" => TargetArch::aarch64,
        other => {
            tracing::warn!(arch = other, "seccomp: unsupported architecture, skipping");
            return Ok(());
        }
    };

    // Deny-list. We never legitimately use any of these. If a dep ever does,
    // the process dies loudly with EPERM and the log points here.
    let denied: &[i64] = &[
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_bpf,
        libc::SYS_userfaultfd,
        libc::SYS_perf_event_open,
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_setns,
        libc::SYS_unshare,
        libc::SYS_reboot,
        libc::SYS_clock_adjtime,
        libc::SYS_clock_settime,
        libc::SYS_settimeofday,
        libc::SYS_swapon,
        libc::SYS_swapoff,
    ];

    let rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> =
        denied.iter().map(|nr| (*nr, Vec::new())).collect();

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .map_err(seccomp_err)?;

    let program: BpfProgram = filter.try_into().map_err(seccomp_err)?;
    seccompiler::apply_filter_all_threads(&program).map_err(seccomp_err)?;

    tracing::info!(
        target: "sandbox",
        denied = denied.len(),
        "seccomp-bpf filter applied"
    );
    Ok(())
}

fn landlock_err(e: impl std::fmt::Display) -> FerromailError {
    FerromailError::ConfigError(format!("Landlock: {e}"))
}

fn seccomp_err(e: impl std::fmt::Display) -> FerromailError {
    FerromailError::ConfigError(format!("seccomp: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_config_construction() {
        let cfg = SandboxConfig {
            config_dir: PathBuf::from("/tmp/ferromail-test"),
            download_dir: PathBuf::from("/tmp/ferromail-test/dl"),
            send_allow_dirs: vec![],
        };
        assert_eq!(cfg.config_dir, PathBuf::from("/tmp/ferromail-test"));
    }

    // We don't test apply() itself because once applied, the filter persists
    // for the process lifetime and would break subsequent tests. Manual
    // verification: run `cargo test --bin ferromail` and check that the
    // server starts without EPERM spam.
}
