use chrono::TimeDelta;
use clap::{Parser, Subcommand};
use env_logger::Env;
use log::{error, info};
use packet_pincer::{Flow, FlowGroup, PacketCapture, PacketOrigin};
use std::{
    fs::File,
    io::BufWriter,
    path::PathBuf,
    process::exit,
    sync::mpsc::{channel, Receiver},
};

const MAX_LINES_FOR_CSV_FILE: u64 = 10_000_000;

#[derive(Default)]
struct ExecutionStats {
    valid_count: u64,
    ignored_count: u64,
    flow_count: u64,
    current_lines_written: u64,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Settings {
    /// Base directory path to write csv output files
    #[arg(short, long)]
    pub csv_output: Option<PathBuf>,

    #[command(subcommand)]
    pub analysis: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Perform the analysis with a given set of network traces
    OfflineAnalysis {
        /// Sets the file or directory of network traces to analyze
        #[arg(short, long, value_name = "FILE/DIRECTORY")]
        traces_dir: PathBuf,
    },
    /// Perform the analysis from captured network traffic
    OnlineAnalysis {
        /// Sets the network interface to capture traces from
        #[arg(short, long, value_name = "INTERFACE")]
        network_interface: pcap::Device,
    },
}

fn create_packet_capture_from_settings(command: &Commands) -> PacketCapture {
    match &command {
        Commands::OfflineAnalysis { traces_dir } => PacketCapture::from_directory(traces_dir),
        Commands::OnlineAnalysis { network_interface } => {
            match PacketCapture::from_device(network_interface.clone()) {
                Ok(capture) => {
                    info!("Device {} opened sucessfully", network_interface.name);
                    capture
                }
                Err(err) => {
                    error!("Could not open device: {}", err);
                    exit(1)
                }
            }
        }
    }
}

fn create_csv_output(mut path: PathBuf) -> Option<BufWriter<File>> {
    let timestamp = chrono::offset::Utc::now().timestamp_millis();
    path.set_extension(format!("{}.csv", timestamp));
    let mut w = BufWriter::new(File::create(path).expect("Unable to create file"));
    let _ = Flow::write_csv_header(&mut w);
    Some(w)
}

fn create_termination_channel() -> Receiver<()> {
    // Setup SIGINT, SIGTERM and SIGHUP handling
    let (tx, rx) = channel();
    ctrlc::set_handler(move || tx.send(()).expect("Could not send signal on channel."))
        .expect("Error setting Ctrl-C handler");
    rx
}

fn evaluate_packets(
    termination_channel: Receiver<()>,
    csv_output: Option<PathBuf>,
    execution_stats: &mut ExecutionStats,
    flows: &mut FlowGroup,
    packet_capture: &mut PacketCapture,
) {
    let mut csv_writer = csv_output
        .as_ref()
        .and_then(|path| create_csv_output(path.clone()));

    loop {
        // TODO: handle faster termination if there are no packets being sent on a device capture
        if termination_channel.try_recv().is_ok() {
            info!("Termination signal received");
            break;
        }

        let process_packet = &mut |_p: PacketOrigin,
                                   link_type: pcap::Linktype,
                                   packet: &pcap::Packet<'_>| {
            if flows.include(link_type, packet) {
                execution_stats.valid_count += 1
            } else {
                execution_stats.ignored_count += 1
            }

            while let Some(flow) = flows.pop_oldest_flow_if_older_than(TimeDelta::seconds(300)) {
                if let Some(ref mut w) = csv_writer {
                    _ = flow.write_csv_value(w);
                    execution_stats.current_lines_written += 1;
                    if MAX_LINES_FOR_CSV_FILE <= execution_stats.current_lines_written {
                        csv_writer = csv_output
                            .as_ref()
                            .and_then(|path| create_csv_output(path.clone()));
                        execution_stats.current_lines_written = 0;
                    }
                }

                execution_stats.flow_count += 1;
            }
        };

        if !packet_capture.try_process_next(process_packet) {
            break;
        }
    }

    while let Some(flow) = flows.pop_oldest_flow() {
        if let Some(ref mut w) = csv_writer {
            _ = flow.write_csv_value(w);
        }
        execution_stats.flow_count += 1;
        execution_stats.current_lines_written += 1;

        if MAX_LINES_FOR_CSV_FILE <= execution_stats.current_lines_written {
            csv_writer = csv_output
                .as_ref()
                .and_then(|path| create_csv_output(path.clone()));
            execution_stats.current_lines_written = 0;
        }
    }
}

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let settings = Settings::parse();

    let termination_channel = create_termination_channel();
    let mut execution_stats = ExecutionStats::default();
    let mut flows = FlowGroup::new();
    let mut packet_capture = create_packet_capture_from_settings(&settings.analysis);

    evaluate_packets(
        termination_channel,
        settings.csv_output,
        &mut execution_stats,
        &mut flows,
        &mut packet_capture,
    );

    info!("{} packets were valid", execution_stats.valid_count);
    info!("{} packets were ignored", execution_stats.ignored_count);
    info!("{} flows detected", execution_stats.flow_count);
}
