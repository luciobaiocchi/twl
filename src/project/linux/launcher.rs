use super::vault::vault_directory_path;
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn find_bubblewrap() -> Option<PathBuf> {
    ["/usr/bin/bwrap", "/usr/local/bin/bwrap"]
        .into_iter()
        .map(PathBuf::from)
        .find(|candidate| {
            fs::symlink_metadata(candidate).is_ok_and(|metadata| {
                metadata.is_file()
                    && metadata.uid() == 0
                    && metadata.permissions().mode() & 0o111 != 0
                    && metadata.permissions().mode() & 0o022 == 0
            })
        })
}

/// Builds the Linux child command, adding only vault masking and PID/proc isolation when
/// Bubblewrap has a trusted system installation. Networking and the host filesystem otherwise
/// remain shared.
pub fn linux_project_child_command(
    program: &str,
    args: &[String],
    overrides: &[(String, String)],
) -> Result<(Command, bool), String> {
    let (mut command, masked) = if let Some(bubblewrap) = find_bubblewrap() {
        let vault_directory = vault_directory_path().map_err(|error| error.to_string())?;
        (
            bubblewrap_command(&bubblewrap, &vault_directory, program, args, overrides),
            true,
        )
    } else {
        (crate::child_command(program, args, overrides), false)
    };
    seal_inherited_descriptors(&mut command)?;
    Ok((command, masked))
}

fn seal_inherited_descriptors(command: &mut Command) -> Result<(), String> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: limit points to writable storage for the duration of getrlimit.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(format!(
            "reading descriptor limit: {}",
            io::Error::last_os_error()
        ));
    }
    let maximum = limit.rlim_cur.min(i32::MAX as libc::rlim_t) as i32;
    // SAFETY: the closure calls only async-signal-safe syscalls after fork. CLOEXEC preserves
    // Rust's exec-error pipe until a successful exec while ensuring no descriptor above stderr
    // reaches Bubblewrap or an unmasked child.
    unsafe {
        command.pre_exec(move || {
            if libc::syscall(
                libc::SYS_close_range,
                3_u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) == 0
            {
                return Ok(());
            }

            for descriptor in 3..maximum {
                let flags = libc::fcntl(descriptor, libc::F_GETFD);
                if flags < 0 {
                    if io::Error::last_os_error().raw_os_error() == Some(libc::EBADF) {
                        continue;
                    }
                    return Err(io::Error::last_os_error());
                }
                if libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0
                    && io::Error::last_os_error().raw_os_error() != Some(libc::EBADF)
                {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    Ok(())
}

fn bubblewrap_command(
    bubblewrap: &Path,
    vault_directory: &Path,
    program: &str,
    args: &[String],
    overrides: &[(String, String)],
) -> Command {
    let mut command = Command::new(bubblewrap);
    command
        .arg("--die-with-parent")
        .arg("--unshare-pid")
        .args(["--dev-bind", "/", "/"])
        .args(["--proc", "/proc"])
        .arg("--tmpfs")
        .arg(vault_directory)
        .arg("--")
        .arg(program)
        .args(args);
    for variable in crate::STRIP {
        command.env_remove(variable);
    }
    for (key, value) in overrides {
        command.env(key, value);
    }
    command
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::os::fd::AsRawFd;

    #[test]
    fn bubblewrap_profile_only_adds_vault_and_process_masking() {
        let command = bubblewrap_command(
            Path::new("/usr/bin/bwrap"),
            Path::new("/home/test/.local/share/twl"),
            "codex",
            &["--version".into()],
            &[("APP_API_KEY".into(), "twl-app-fake".into())],
        );
        let arguments: Vec<_> = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            arguments,
            [
                "--die-with-parent",
                "--unshare-pid",
                "--dev-bind",
                "/",
                "/",
                "--proc",
                "/proc",
                "--tmpfs",
                "/home/test/.local/share/twl",
                "--",
                "codex",
                "--version",
            ]
        );
        assert!(!arguments.iter().any(|argument| argument == "--unshare-net"));
    }

    #[test]
    fn child_does_not_inherit_open_descriptors() {
        let file = File::open("/dev/null").unwrap();
        let descriptor = file.as_raw_fd();
        // Deliberately make this descriptor inheritable so the launcher hardening is tested.
        assert_eq!(unsafe { libc::fcntl(descriptor, libc::F_SETFD, 0) }, 0);
        let args = vec!["-c".into(), format!("test ! -e /proc/self/fd/{descriptor}")];
        let mut command = crate::child_command("/bin/sh", &args, &[]);
        seal_inherited_descriptors(&mut command).unwrap();
        assert!(command.status().unwrap().success());
    }
}
