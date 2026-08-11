use std::process::Command;

fn main() {
    let output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output();

    match output {
        Ok(output) if output.status.success() => {
            let git_hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
            println!("cargo:rustc-env=GIT_HASH={}", git_hash);
        }
        _ => {
            println!("cargo:rustc-env=GIT_HASH=unknown");
        }
    }

    let output = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output();

    match output {
        Ok(output) if output.status.success() => {
            let git_branch = String::from_utf8_lossy(&output.stdout).trim().to_string();
            println!("cargo:rustc-env=GIT_BRANCH={}", git_branch);
        }
        _ => {
            println!("cargo:rustc-env=GIT_BRANCH=unknown");
        }
    }

    let output = Command::new("git")
        .args(["log", "-1", "--format=%cd", "--date=short"])
        .output();

    match output {
        Ok(output) if output.status.success() => {
            let git_date = String::from_utf8_lossy(&output.stdout).trim().to_string();
            println!("cargo:rustc-env=GIT_DATE={}", git_date);
        }
        _ => {
            println!("cargo:rustc-env=GIT_DATE=unknown");
        }
    }

    println!("cargo:rerun-if-changed=../.git/HEAD");
}
