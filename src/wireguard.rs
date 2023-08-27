use crate::rpc::PeerDef;
use std::ffi::OsStr;
use std::io::Error as IoError;
use std::io::ErrorKind;
use std::io::Result as IoResult;
use std::process::{Command, Stdio};
use std::string::ToString;

const WGPATH: &str = "/usr/bin/wg";

fn exec<I, S>(path: &str, args: I) -> IoResult<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut cmd = Command::new(path);
    let output = cmd.args(args).stderr(Stdio::inherit()).output()?;

    if !output.status.success() {
        let msg = format!(
            "Command '{:?}' exited with {}",
            cmd,
            output
                .status
                .code()
                .map(|i| i.to_string())
                .unwrap_or(String::from("Signal"))
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
        .filter_map(PeerDef::from_wg_dump)
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
                Err(IoError::new(ErrorKind::Other, msg))
            }
        }
    } else {
        let res = match interfaces.next() {
            Some(r) => r,
            None => {
                let msg = "No wireguard interfaces found".to_string();
                return Err(IoError::new(ErrorKind::Other, msg));
            }
        };

        if interfaces.count() > 0 {
            let msg = "Multiple wireguard interfaces found,
                      please specify an interface name manually"
                .to_string();
            return Err(IoError::new(ErrorKind::Other, msg));
        }

        Ok(res.to_string())
    }
}

pub fn delete_peer(ifname: &str, peer_key: &str) -> IoResult<()> {
    exec("/usr/bin/wg", ["set", ifname, "peer", peer_key, "remove"])?;
    Ok(())
}

pub fn add_peers<'a, T>(ifname: &str, peers: T) -> IoResult<()>
where
    T: IntoIterator<Item = &'a PeerDef>,
{
    let args = [String::from("set"), String::from(ifname)]
        .into_iter()
        .chain(peers.into_iter().flat_map(|p| p.to_wg_set()));
    exec(WGPATH, args)?;
    Ok(())
}
