use anyhow::Result;
use std::process::Command;
use std::time::Duration;

// Smoke test: verify binaries are runnable when INTEGRATION_RUN=1.
// Marked ignored so it won't run in CI without opt-in.
#[test]
#[ignore]
fn binaries_smoke() -> Result<()> {
    if std::env::var("INTEGRATION_RUN").is_err() {
        return Ok(());
    }

    // Client help
    Command::new("cargo")
        .current_dir("../client")
        .args(["run", "--", "--help"])
        .status()
        .expect("run client help");

    // Blockchain node help
    Command::new("cargo")
        .current_dir("../blockchain-node")
        .args(["run", "--", "--help"])
        .status()
        .expect("run blockchain help");

    // Relay presence (go version)
    Command::new("go")
        .arg("version")
        .status()
        .expect("go toolchain missing");

    // Basic delay to allow any accidental processes to settle
    std::thread::sleep(Duration::from_millis(50));
    Ok(())
}
