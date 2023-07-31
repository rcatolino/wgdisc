mod client;
mod server;
mod rpc;

use clap::{value_parser, Arg, ArgAction, Command};

use client::client_main;
use server::server_main;

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
                .arg(Arg::new("host").required(true))
                .arg(
                    Arg::new("port")
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
