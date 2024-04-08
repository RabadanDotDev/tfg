use std::path::PathBuf;
use clap::{Parser, Subcommand};
use packet_pincer::PcapList;
use pcap::Device;

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
            let _pcap_path_list = PcapList::from(&traces_dir);
            println!("{:?}", _pcap_path_list);
            todo!()
        },
        Commands::OnlineAnalysis { network_interface: _ } => {
            todo!()
        }
    }
}
