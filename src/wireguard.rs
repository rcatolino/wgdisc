use crate::rpc::PeerDef;
use std::ffi::OsStr;
use std::io::Error as IoError;
use std::io::ErrorKind;
use std::io::Result as IoResult;
use std::process::Command;

const WGPATH: &'static str = "/usr/bin/wg";

fn exec<I, S>(path: &str, args: I) -> IoResult<String>
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

pub fn find_interface(filter: Option<&str>) -> IoResult<String> {
    let stdout = exec("/usr/bin/wg", ["show", "interfaces"])?;
    let mut interfaces = stdout.trim_end().split_terminator('\n');

    if let Some(ifname) = filter {
        match interfaces.find(|name| name == &ifname) {
            Some(name) => Ok(name.to_string()),
            None => {
                let msg = format!("No wireguard interface named {} found", ifname);
                return Err(IoError::new(ErrorKind::Other, msg));
            }
        }
    } else {
        let res = match interfaces.nth(0) {
            Some(r) => r,
            None => {
                let msg = format!("No wireguard interfaces found");
                return Err(IoError::new(ErrorKind::Other, msg));
            }
        };

        if interfaces.count() > 0 {
            let msg = format!(
                "Multiple wireguard interfaces found,
                              please specify an interface name manually"
            );
            return Err(IoError::new(ErrorKind::Other, msg));
        }

        Ok(res.to_string())
    }
}

pub fn add_peers<'a, T>(ifname: &str, peers: T) -> IoResult<()>
where
    T: IntoIterator<Item = &'a PeerDef>,
{
    let args = [String::from("set"), String::from(ifname)]
        .into_iter()
        .chain(peers.into_iter().map(|p| p.to_wg_set()).flatten());
    exec(WGPATH, args)?;
    Ok(())
}
