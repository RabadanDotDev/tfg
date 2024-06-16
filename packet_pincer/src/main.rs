use chrono::TimeDelta;
use clap::{Parser, Subcommand};
use env_logger::Env;
use log::{error, info};
use packet_pincer::{FlowGroup, GroundTruth, PacketCapture, PacketOrigin, TransportFlow};

use std::{
    fs::File,
    io::{BufWriter, Write},
    path::PathBuf,
    process::exit,
    sync::mpsc::{channel, Receiver},
};

const MAX_LINES_FOR_CSV_FILE: u64 = 10_000_000;

#[derive(Default)]
struct ExecutionStats {
    flow_count: u64,
    current_lines_written: u64,
    total_count: u64,
    valid_count: u64,
    packet_error_on_slice_count: u64,
    packet_error_on_slice_reasembled_count: u64,
    packet_could_not_find_net_layer_count: u64,
    packet_could_not_find_transport_layer_count: u64,
    unsupported_link_type_count: u64,
    unsupported_transport_type_count: u64,
    discarded_fragments_ignored_on_reassembly_count: u64,
    discarded_fragments_no_reassembly_count: u64,
}

impl ExecutionStats {
    fn print_info_results(&self) {
        info!("{} packets were seen", self.total_count);
        if self.valid_count != 0 {
            info!("{} packets were valid", self.valid_count);
        }
        if self.packet_error_on_slice_count != 0 {
            info!(
                "{} packets had issues on slicing",
                self.packet_error_on_slice_count
            );
        }
        if self.packet_error_on_slice_reasembled_count != 0 {
            info!(
                "{} reasembled packets had issues on slicing (invalid/inconsistent fields)",
                self.packet_error_on_slice_reasembled_count
            );
        }
        if self.packet_could_not_find_net_layer_count != 0 {
            info!(
                "{} packets didn't contain a valid/known network layer",
                self.packet_could_not_find_net_layer_count
            );
        }
        if self.packet_could_not_find_transport_layer_count != 0 {
            info!(
                "{} packets didn't contain a valid/known transport layer",
                self.packet_could_not_find_transport_layer_count
            );
        }
        if self.unsupported_link_type_count != 0 {
            info!(
                "{} packets came from an unsupported link type",
                self.unsupported_link_type_count
            );
        }
        if self.unsupported_transport_type_count != 0 {
            info!(
                "{} packets came from an unsupported transport type",
                self.unsupported_transport_type_count
            );
        }
        if self.discarded_fragments_ignored_on_reassembly_count != 0 {
            info!(
                "{} fragments had to be discarded on reassembling packets (duplicates, possible overlaps, etc.)",
                self.discarded_fragments_ignored_on_reassembly_count
            );
        }
        if self.discarded_fragments_no_reassembly_count != 0 {
            info!(
                "{} fragments had to be discarded without an associated reassembly",
                self.discarded_fragments_no_reassembly_count
            );
        }
    }
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Settings {
    /// Base directory path to write csv output files
    #[arg(short, long)]
    pub csv_output_base: Option<PathBuf>,

    /// Output tags on the stdout. Ignored if output_base_csv is set
    #[arg(short, long)]
    pub stdout_output: bool,

    /// File in a csv format indicating the tags that should be tried to be
    /// assigned to the flows. It should contain the colums source_ip, dest_ip,
    /// timestamp_micro_start, timestamp_micro_end and label
    #[arg(short, long)]
    pub ground_truth_csv: Option<PathBuf>,

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

fn create_csv_output(mut path: PathBuf, label_column: bool) -> Option<BufWriter<Box<dyn Write>>> {
    let timestamp = chrono::offset::Utc::now().timestamp_millis();
    path.set_extension(format!("{}.csv", timestamp));
    let file = File::create(path).expect("Unable to create file");
    let writer: Box<dyn Write> = Box::new(file);
    let mut w = BufWriter::new(writer);
    let _ = TransportFlow::write_csv_header(&mut w, label_column);
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
    csv_output_base: Option<PathBuf>,
    stdout_output: bool,
    ground_truth: Option<GroundTruth>,
    execution_stats: &mut ExecutionStats,
    flows: &mut FlowGroup,
    packet_capture: &mut PacketCapture,
) {
    // Define flow label assignation
    let assign_flow_label = |flow: &mut TransportFlow| {
        if let Some(ref ground_truth) = ground_truth {
            match ground_truth.find_label(flow) {
                Some(label) => flow.set_label(label),
                None => flow.set_label("unknown".into()),
            }
        }
    };

    // Init csv writer
    let mut csv_writer: Option<BufWriter<Box<dyn Write>>> = match (&csv_output_base, stdout_output) {
        (Some(path), _) => create_csv_output(path.clone(), ground_truth.is_some()),
        (None, true) => Some(BufWriter::new( Box::new(std::io::stdout()))), 
        (None, false) => None
    };
    

    // Define writing a closed flow to file
    let mut write_closed_flow = |flow: TransportFlow| {
        if let Some(ref mut w) = csv_writer {
            _ = flow.write_csv_value(w, ground_truth.is_some());
            execution_stats.current_lines_written += 1;
            if MAX_LINES_FOR_CSV_FILE <= execution_stats.current_lines_written && csv_output_base.as_ref().is_some() {
                csv_writer = csv_output_base
                    .as_ref()
                    .and_then(|path| create_csv_output(path.clone(), ground_truth.is_some()));
                execution_stats.current_lines_written = 0;
            }
        }
    };

    // Define packet processing
    let process_packet =
        &mut |_p: PacketOrigin, link_type: pcap::Linktype, packet: &pcap::Packet<'_>| {
            execution_stats.total_count += 1;

            match flows.include(link_type, packet) {
                Ok((valid, discarded)) => {
                    execution_stats.valid_count += u64::from(valid);
                    execution_stats.discarded_fragments_ignored_on_reassembly_count +=
                        u64::from(discarded);
                }
                Err(parse_error) => match parse_error {
                    packet_pincer::ParseError::ErrorOnSlicingPacket(_) => {
                        execution_stats.packet_error_on_slice_count += 1
                    }
                    packet_pincer::ParseError::ErrorOnSlicingReassembledPacket { .. } => {
                        execution_stats.packet_error_on_slice_reasembled_count += 1
                    }
                    packet_pincer::ParseError::MissingNetworkLayer => {
                        execution_stats.packet_could_not_find_net_layer_count += 1
                    }
                    packet_pincer::ParseError::MissingTransportLayer => {
                        execution_stats.packet_could_not_find_transport_layer_count += 1
                    }
                    packet_pincer::ParseError::UnsupportedLinkType => {
                        execution_stats.unsupported_link_type_count += 1
                    }
                    packet_pincer::ParseError::UnsupportedTransportLayer => {
                        execution_stats.unsupported_transport_type_count += 1
                    }
                },
            }

            // Close transport flows
            while let Some(mut flow) =
                flows.pop_oldest_transport_flow_if_older_than(TimeDelta::seconds(120))
            {
                execution_stats.flow_count += 1;
                assign_flow_label(&mut flow);
                write_closed_flow(flow);
            }

            // Close network flows
            while let Some(fragments) =
                flows.pop_oldest_network_flow_if_older_than(TimeDelta::seconds(30))
            {
                execution_stats.discarded_fragments_no_reassembly_count += u64::from(fragments);
            }
        };

    // Evaluate packets until running out of them or being interrupted
    loop {
        // TODO: handle faster termination if there are no packets being sent on a device capture
        if termination_channel.try_recv().is_ok() {
            info!("Termination signal received");
            break;
        }

        if !packet_capture.try_process_next(process_packet) {
            info!("Packet capture has no more packets to process");
            break;
        }
    }

    // Close remaining transport flows
    while let Some(mut flow) = flows.pop_oldest_transport_flow() {
        execution_stats.flow_count += 1;
        assign_flow_label(&mut flow);
        write_closed_flow(flow);
    }

    // Close remaining network flows
    while let Some(fragments) = flows.pop_oldest_network_flow() {
        execution_stats.discarded_fragments_no_reassembly_count += u64::from(fragments);
    }
}

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let settings = Settings::parse();

    let termination_channel = create_termination_channel();
    let mut execution_stats = ExecutionStats::default();
    let mut flows = FlowGroup::new();
    let mut packet_capture = create_packet_capture_from_settings(&settings.analysis);
    let ground_truth = match settings.ground_truth_csv {
        Some(path) => match GroundTruth::from_file(path) {
            Ok(ground_truth) => Some(ground_truth),
            Err(err) => {
                error!("Error loading ground truth: {}", err);
                exit(2);
            }
        },
        None => None,
    };

    evaluate_packets(
        termination_channel,
        settings.csv_output_base,
        settings.stdout_output,
        ground_truth,
        &mut execution_stats,
        &mut flows,
        &mut packet_capture,
    );

    execution_stats.print_info_results();
}
