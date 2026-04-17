#![no_main]
//! Fuzz the download sandbox: arbitrary "filename" must never yield a
//! download_path outside the sandbox dir.

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn sandbox() -> &'static (tempfile::TempDir, ferromail::sandbox::DownloadSandbox) {
    static S: OnceLock<(tempfile::TempDir, ferromail::sandbox::DownloadSandbox)> = OnceLock::new();
    S.get_or_init(|| {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let dir = tmp.path().to_path_buf();
        let sb = ferromail::sandbox::DownloadSandbox::new(
            dir,
            10 * 1024 * 1024,
            vec![
                "txt".into(),
                "pdf".into(),
                "bin".into(),
                "dat".into(),
                "png".into(),
            ],
            vec![],
        )
        .expect("sandbox");
        (tmp, sb)
    })
}

fuzz_target!(|input: String| {
    let (tmp, sb) = sandbox();
    // Sanitize first (normal caller path) then hand to sandbox.
    let clean = ferromail::sanitize::filename::sanitize_filename(&input, 0);
    if let Ok(path) = sb.download_path("1", &clean) {
        assert!(
            path.starts_with(tmp.path()),
            "sandbox escape: input={input:?} clean={clean:?} path={path:?}"
        );
    }
});
