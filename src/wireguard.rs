use std::io::Error as IoError;
use std::io::ErrorKind;
use std::io::Result as IoResult;
use std::process::Command;
use crate::rpc::PeerDef;

fn exec<'a>(path: &str, args: &[&str]) -> IoResult<String> {
    let output = Command::new(path)
        .args(args)
        .output()?;

    if !output.status.success() {
        let msg = format!(
            "Error {:?} executing '{} {}'",
            output.status.code(),
            path, args.join(" ")
        );
        return Err(IoError::new(ErrorKind::Other, msg));
    }

    String::from_utf8(output.stdout).or(Err(IoError::new(
        ErrorKind::Other,
        "Unsupported encoding in command output",
    )))
}

fn parse_peer(line: &str) -> Option<PeerDef> {
    let conf: Vec<&str> = line.split_terminator('\t').collect();
    let peer = PeerDef {
        peer_key: conf[0].to_string(),
        endpoint: conf[2].rsplit_once(':').and_then(|(ip, port)| {
            Some((ip.parse().ok()?, port.parse().ok()?))
        })?,
        allowed_ips: conf[3].split_terminator(',').filter_map(|ipmask| {
            let (ip, mask) = ipmask.rsplit_once('/')?;
            Some((ip.parse().ok()?, mask.parse().ok()?))
        }).collect(),
    };

    Some(peer)
}

pub fn get_peers(ifname: &str) -> IoResult<Vec<PeerDef>> {
    let stdout = exec("/usr/bin/wg", &["show", ifname, "dump"])?;
    Ok(stdout.trim_end().split_terminator('\n').skip(1).filter_map(|line| {
        parse_peer(line)
    }).collect())
}

pub fn list() -> IoResult<String> {
    let stdout = exec("/usr/bin/wg", &["show", "interfaces"])?;
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
