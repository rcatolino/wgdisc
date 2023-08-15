mod client;
mod rpc;
mod server;
mod wireguard;

use clap::{value_parser, Arg, ArgAction, Command};

use client::client_main;
use server::server_main;
use std::net::IpAddr;

fn main() -> std::io::Result<()> {
    let matches = Command::new("wgdisc")
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::SetTrue),
        )
        .subcommand_required(true)
        .subcommand(
            Command::new("client")
                .arg(Arg::new("host").required(true))
                .arg(
                    Arg::new("port")
                        .value_parser(value_parser!(u16))
                        .default_value("31250"),
                ),
        )
        .subcommand(
            Command::new("server")
                .arg(
                    Arg::new("address")
                        .short('a')
                        .long("address")
                        .value_parser(value_parser!(IpAddr))
                        .next_line_help(true)
                        .help(
                            "Listen on this address only. \
                               The address must be assigned to the wireguard interface.\n\
                               By default, the server listens on every address assigned \
                               to the interface.",
                        ),
                )
                .arg(
                    Arg::new("port")
                        .short('p')
                        .long("port")
                        .value_parser(value_parser!(u16))
                        .default_value("31250"),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("client", submatches)) => client_main(submatches)?,
        Some(("server", submatches)) => server_main(submatches)?,
        _ => unreachable!("Unknown or missing subcommand"),
    };

    Ok(())
}
