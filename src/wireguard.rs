use std::io::Error as IoError;
use std::io::ErrorKind;
use std::io::Result as IoResult;
use std::process::Command;

pub fn list() -> IoResult<String> {
    let output = Command::new("/usr/bin/wg")
        .args(["show", "interfaces"])
        .output()?;
    if !output.status.success() {
        let msg = format!(
            "Error {:?} executing 'wg show interfaces'",
            output.status.code()
        );
        return Err(IoError::new(ErrorKind::Other, msg));
    }

    let stdout = String::from_utf8(output.stdout).or(Err(IoError::new(
        ErrorKind::Other,
        "Unsupported encoding in interface name",
    )))?;

    let mut interfaces = stdout.trim_end().split_terminator('\n');

    let result = match interfaces.nth(0) {
        Some(r) => r,
        None => {
            let msg = format!("No wireguard interfaces found");
            return Err(IoError::new(ErrorKind::Other, msg));
        }
    };

    if interfaces.count() > 0 {
        let msg = format!("Multiple wireguard interfaces found");
        return Err(IoError::new(ErrorKind::Other, msg));
    }

    Ok(result.to_string())
}
