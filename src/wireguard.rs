use crate::rpc::PeerDef;
use std::ffi::OsStr;
use std::io::Error as IoError;
use std::io::ErrorKind;
use std::io::Result as IoResult;
use std::process::Command;

const WGPATH: &'static str = "/usr/bin/wg";

// fn exec<'a>(path: &str, args: &[&str]) -> IoResult<String> {
fn exec<'a, I, S>(path: &str, args: I) -> IoResult<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut cmd = Command::new(path);
    let output = cmd.args(args).output()?;

    if !output.status.success() {
        let msg = format!(
            "Error {:?} executing '{} {:?}'",
            output.status.code(),
            path,
            cmd
        );
        return Err(IoError::new(ErrorKind::Other, msg));
    }

    String::from_utf8(output.stdout).or(Err(IoError::new(
        ErrorKind::Other,
        "Unsupported encoding in command output",
    )))
}

pub fn get_peers(ifname: &str) -> IoResult<Vec<PeerDef>> {
    let stdout = exec("/usr/bin/wg", ["show", ifname, "dump"])?;
    Ok(stdout
        .trim_end()
        .split_terminator('\n')
        .skip(1)
        .filter_map(|line| PeerDef::from_wg_dump(line))
        .collect())
}

pub fn list() -> IoResult<String> {
    let stdout = exec("/usr/bin/wg", ["show", "interfaces"])?;
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

pub fn add_peers(ifname: &str, peers: &[&PeerDef]) -> IoResult<()> {
    /*
    let args = [String::from("set"), String::from(ifname)]
        .into_iter()
        .chain(peers.into_iter().map(|p| p.to_wg_set()).flatten());
        */
    let args = ["set", ifname]
        .into_iter()
        .chain(peers.into_iter().map(|p| p.to_wg_set()).flatten());
    let _stdout = exec(WGPATH, args);
    Ok(())
}
