mod cidr;
mod client;
mod rpc;
mod server;

use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};

use client::client_main;
use server::server_main;
use std::{net::IpAddr, process::ExitCode};

fn main() -> ExitCode {
    let matches = Command::new("wgdisc")
        .override_usage("wgdisc [interface] subcommand [options]")
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("interface")
                .next_line_help(true)
                .help(
                    "Wireguard interface name. \
                   Only required if multiple wireguard \n\
                   interfaces exist on the system",
                )
                .required(false),
        )
        .subcommand_required(true)
        .subcommand(
            Command::new("client")
                .arg(
                    Arg::new("address")
                        .short('a')
                        .long("address")
                        .required(true)
                        .help("Address of the discovery server"),
                )
                .arg(
                    Arg::new("port")
                        .short('p')
                        .long("port")
                        .value_parser(value_parser!(u16))
                        .default_value("31250"),
                )
                .arg(
                    Arg::new("override")
                        .short('o')
                        .long("override")
                        .value_delimiter(',')
                        .value_name("pubkey>+<0.0.0.0/0>,<pubkey>-<192.168.2.0/24")
                        .next_line_help(true)
                        .help(
                            "Override allowed-ips for peer. \
                              IPs prefixed with + will be added to the list of allowed ips, \
                              IPs prefixed with - will be removed, if present.",
                        ),
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

    if let Err(e) = run_app(matches) {
        println!("Error : {:?}", e);
    }

    // There's no reason to exit with success, it's always a failure
    ExitCode::FAILURE
}

fn run_app(matches: ArgMatches) -> wireguard_uapi::netlink::Result<()> {
    let filter = matches.get_one::<String>("interface");

    match matches.subcommand() {
        Some(("client", submatches)) => client_main(filter, submatches)?,
        Some(("server", submatches)) => server_main(filter, submatches)?,
        _ => unreachable!("Unknown or missing subcommand"),
    };

    Ok(())
}
