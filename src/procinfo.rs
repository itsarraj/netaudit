use std::fs;
use std::path::Path;

/// Finds the PID whose open file descriptors include a socket with the
/// given inode, by walking `<proc_root>/<pid>/fd/*` — same technique
/// `whatport` uses elsewhere in this workspace, reimplemented here rather
/// than shared, since each tool under `tools/` is a standalone crate
/// meant to be extractable on its own (see `tools/README.md`).
/// `proc_root` is a parameter so this is testable against a fake tree.
pub fn find_pid_for_inode(proc_root: &Path, inode: u64) -> Option<u32> {
    let target = format!("socket:[{inode}]");
    let entries = fs::read_dir(proc_root).ok()?;
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(fds) = fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if let Ok(link) = fs::read_link(fd.path()) {
                if link.to_string_lossy() == target {
                    return Some(pid);
                }
            }
        }
    }
    None
}

pub fn process_name(proc_root: &Path, pid: u32) -> Option<String> {
    let comm = fs::read_to_string(proc_root.join(pid.to_string()).join("comm")).ok()?;
    let trimmed = comm.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn fake_proc_root(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("netaudit-test-{}-{}", std::process::id(), name))
    }

    #[test]
    fn finds_pid_for_a_matching_inode() {
        let root = fake_proc_root("match");
        let fd_dir = root.join("500/fd");
        fs::create_dir_all(&fd_dir).unwrap();
        symlink("socket:[777]", fd_dir.join("4")).unwrap();
        fs::write(root.join("500/comm"), "postgres\n").unwrap();

        assert_eq!(find_pid_for_inode(&root, 777), Some(500));
        assert_eq!(process_name(&root, 500), Some("postgres".to_string()));

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn no_match_returns_none_not_an_error() {
        let root = fake_proc_root("nomatch");
        fs::create_dir_all(&root).unwrap();
        assert_eq!(find_pid_for_inode(&root, 999), None);
        fs::remove_dir_all(&root).ok();
    }
}
