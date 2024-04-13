use clap::{Parser, Subcommand};
use packet_pincer::OfflineCaptureList;
use pcap::{Device, Packet};
use std::path::{Path, PathBuf};

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

    match settings.analysis {
        Commands::OfflineAnalysis { traces_dir } => {
            let mut pcap_path_list = OfflineCaptureList::from(&traces_dir);

            let mut process_state: i32 = 0;
            let mut process = |_p: &Path, a: &Packet<'_>| {
                println!(
                    "{:?} - {:?} - {:?}",
                    process_state, a.header.ts.tv_sec, a.header.ts.tv_usec
                );
                process_state = process_state + 1;
            };

            pcap_path_list.try_process_next(&mut process);
            pcap_path_list.try_process_next(&mut process);
            pcap_path_list.try_process_next(&mut process);
            pcap_path_list.try_process_next(&mut process);

            todo!()
        }
        Commands::OnlineAnalysis {
            network_interface: _,
        } => {
            todo!()
        }
    }
}
