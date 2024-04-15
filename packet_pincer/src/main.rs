use chrono::TimeDelta;
use clap::{Parser, Subcommand};
use packet_pincer::{Device, Flow, FlowGroup, Linktype, PacketCapture, PacketOrigin};
use std::{
    fs::File,
    io::BufWriter,
    path::PathBuf,
    process::exit,
    sync::mpsc::{channel, Receiver},
};

#[derive(Default)]
struct ExecutionStats {
    valid_count: i64,
    ignored_count: i64,
    flow_count: i64,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Settings {
    /// Write flow statistics to the given file
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
        network_interface: Device,
    },
}

fn create_packet_capture_from_settings(command: &Commands) -> PacketCapture {
    match &command {
        Commands::OfflineAnalysis { traces_dir } => PacketCapture::from_directory(&traces_dir),
        Commands::OnlineAnalysis { network_interface } => {
            match PacketCapture::from_device(network_interface.clone()) {
                Ok(capture) => capture,
                Err(error) => {
                    println!("Could not open device: {}", error);
                    exit(1)
                }
            }
        }
    }
}

fn create_csv_output(path: Option<PathBuf>) -> Option<BufWriter<File>> {
    let mut w = BufWriter::new(File::create(path?).expect("Unable to create file"));
    Flow::write_csv_header(&mut w).ok()?;
    Some(w)
}

fn create_termination_channel() -> Receiver<()> {
    // Setup SIGINT, SIGTERM and SIGHUP handling
    let (tx, rx) = channel();
    ctrlc::set_handler(move || tx.send(()).expect("Could not send signal on channel."))
        .expect("Error setting Ctrl-C handler");
    return rx;
}

fn evaluate_packet(
    execution_stats: &mut ExecutionStats,
    flows: &mut FlowGroup,
    csv_writer: &mut Option<BufWriter<File>>,
    link_type: Linktype,
    packet: &pcap::Packet<'_>,
) {
    if flows.include(link_type, packet) {
        execution_stats.valid_count = execution_stats.valid_count + 1
    } else {
        execution_stats.ignored_count = execution_stats.ignored_count + 1
    }

    while let Some(flow) = flows.pop_oldest_flow_if_older_than(TimeDelta::seconds(300)) {
        if let Some(ref mut w) = csv_writer {
            _ = flow.write_csv_value(w);
        }
        execution_stats.flow_count = execution_stats.flow_count + 1;
    }
}

fn close_remaining_flows(
    execution_stats: &mut ExecutionStats,
    flows: &mut FlowGroup,
    csv_writer: &mut Option<BufWriter<File>>,
) {
    while let Some(flow) = flows.pop_oldest_flow() {
        if let Some(ref mut w) = csv_writer {
            _ = flow.write_csv_value(w);
        }
        execution_stats.flow_count = execution_stats.flow_count + 1;
    }
}

fn evaluate_packets(
    termination_channel: Receiver<()>,
    execution_stats: &mut ExecutionStats,
    flows: &mut FlowGroup,
    csv_writer: &mut Option<BufWriter<File>>,
    packet_capture: &mut PacketCapture,
) {
    loop {
        // TODO: handle faster termination if there are no packets being sent on a device capture
        if termination_channel.try_recv().is_ok() {
            println!("Interrupt caught. Terminating...");
            break;
        }

        if !packet_capture.try_process_next(
            &mut |_p: PacketOrigin, link_type: Linktype, packet: &pcap::Packet<'_>| {
                evaluate_packet(execution_stats, flows, csv_writer, link_type, packet);
            },
        ) {
            break;
        }
    }

    close_remaining_flows(execution_stats, flows, csv_writer);
}

fn main() {
    let settings = Settings::parse();

    let termination_channel = create_termination_channel();
    let mut execution_stats = ExecutionStats::default();
    let mut flows = FlowGroup::new();
    let mut csv_writer = create_csv_output(settings.csv_output);
    let mut packet_capture = create_packet_capture_from_settings(&settings.analysis);

    evaluate_packets(
        termination_channel,
        &mut execution_stats,
        &mut flows,
        &mut csv_writer,
        &mut packet_capture,
    );

    println!("{} packets were valid", execution_stats.valid_count);
    println!("{} packets were ignored", execution_stats.ignored_count);
    println!("{} flows detected", execution_stats.flow_count);
}
