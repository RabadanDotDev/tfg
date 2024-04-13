use clap::{Parser, Subcommand};
use packet_pincer::{try_parse_packet, FlowIdentifier, Device, Linktype, Packet, PacketCapture, PacketOrigin};
use std::{path::PathBuf, process::exit, sync::mpsc::channel};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Settings {
    #[command(subcommand)]
    pub analysis: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    // Perform the analysis with a given set of network traces
    OfflineAnalysis {
        /// Sets the file or directory of network traces to analyze
        #[arg(short, long, value_name = "FILE/DIRECTORY")]
        traces_dir: PathBuf,
    },
    // Perform the analysis from captured network traffic
    OnlineAnalysis {
        /// Sets the network interface to capture traces from
        #[arg(short, long, value_name = "INTERFACE")]
        network_interface: Device,
    },
}

fn main() {
    let settings = Settings::parse();

    let mut packet_capture = match settings.analysis {
        Commands::OfflineAnalysis { traces_dir } => PacketCapture::from_directory(&traces_dir),
        Commands::OnlineAnalysis { network_interface } => {
            match PacketCapture::from_device(network_interface) {
                Ok(capture) => capture,
                Err(error) => {
                    println!("Could not open device: {}", error);
                    exit(1)
                }
            }
        }
    };

    let mut packet_count: i32 = 0;
    let mut valid_count: i32 = 0;
    let mut ignored_count: i32 = 0;
    let mut process = |_p: PacketOrigin, link_type: Linktype, packet: &Packet<'_>| {
        match try_parse_packet(link_type, packet) {
            Some(packet) => match FlowIdentifier::from_sliced_packet(packet) {
                Some(_flow_identifier) => valid_count = valid_count + 1,
                None => ignored_count = ignored_count + 1
            }
            None => ignored_count = ignored_count + 1,
        }
        packet_count = packet_count + 1;
    };

    // Setup SIGINT, SIGTERM and SIGHUP handling
    // TODO: handle faster termination if there are no packets being sent on a device capture
    let (tx, rx) = channel();
    ctrlc::set_handler(move || tx.send(()).expect("Could not send signal on channel."))
        .expect("Error setting Ctrl-C handler");

    // Loop until completion or interrupted
    loop {
        match rx.try_recv() {
            Ok(_) => {
                println!("Interrupt caught. Terminating...");
                break;
            }
            Err(_) => match packet_capture.try_process_next(&mut process) {
                true => continue,
                false => break,
            },
        }
    }

    println!("{} packets have been processed", packet_count);
    println!("{} packets were valid", valid_count);
    println!("{} packets were invalid", ignored_count);
}
