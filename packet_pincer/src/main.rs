use clap::{Parser, Subcommand};
use packet_pincer::{PacketOrigin, PacketCapture, Packet, Device};
use std::{path::PathBuf, process::exit};

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
        Commands::OfflineAnalysis { traces_dir } => {
            PacketCapture::from_directory(&traces_dir)
        }
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
    let mut process = |_p: PacketOrigin, a: &Packet<'_>| {
        println!(
            "{:?} - timestamp: {:?}.{:?}",
            packet_count, a.header.ts.tv_sec, a.header.ts.tv_usec
        );
        packet_count = packet_count + 1;
    };

    loop {
        packet_capture.try_process_next(&mut process);
    }
}
