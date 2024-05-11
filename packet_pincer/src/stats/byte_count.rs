use super::{running_stat::RunningStat, FlowStat, FlowTimes};
use crate::{packet_flow::FragmentReasemblyInformation, packet_parse::TransportFlowIdentifier};
use std::{
    io::{BufWriter, Error, Write},
    net::IpAddr,
};

#[derive(Debug)]
pub struct ByteCount {
    bidirectional: RunningStat,
    forward: RunningStat,
    backward: RunningStat,
}

fn extract_count(
    packet_header: &pcap::PacketHeader,
    reasembly_information: Option<&FragmentReasemblyInformation>,
) -> u64 {
    match reasembly_information {
        Some(reasembly_information) => reasembly_information.total_bytes_received_count.into(),
        None => packet_header.len.into(),
    }
}

impl FlowStat for ByteCount {
    fn from_packet(
        _identifier: &TransportFlowIdentifier,
        _flow_times: &FlowTimes,
        packet_header: &pcap::PacketHeader,
        _sliced_packet: &etherparse::SlicedPacket,
        reasembly_information: Option<&FragmentReasemblyInformation>,
    ) -> Self {
        let count = extract_count(packet_header, reasembly_information);

        let mut bidirectional = RunningStat::new();
        let mut forward = RunningStat::new();
        let backward = RunningStat::new();

        bidirectional.include(count);
        forward.include(count);

        ByteCount {
            bidirectional,
            forward,
            backward,
        }
    }
    fn include(
        &mut self,
        identifier: &TransportFlowIdentifier,
        _flow_times: &FlowTimes,
        packet_header: &pcap::PacketHeader,
        sliced_packet: &etherparse::SlicedPacket,
        reasembly_information: Option<&FragmentReasemblyInformation>,
    ) {
        let count = extract_count(packet_header, reasembly_information);

        let src_ip = match &sliced_packet.net {
            Some(header) => match header {
                etherparse::NetSlice::Ipv4(v) => IpAddr::V4(v.header().source_addr()),
                etherparse::NetSlice::Ipv6(v) => IpAddr::V6(v.header().source_addr()),
            },
            None => panic!("Unexpected sliced packet without net layer"),
        };

        self.bidirectional.include(count);

        if src_ip == identifier.source_ip {
            self.forward.include(count);
        } else {
            self.backward.include(count);
        }
    }
    fn write_csv_header<T: ?Sized + std::io::Write>(
        writer: &mut BufWriter<T>,
    ) -> Result<(), Error> {
        write!(writer, "bidirectional_packet_bytes_sum,")?;
        write!(writer, "bidirectional_packet_bytes_max,")?;
        write!(writer, "bidirectional_packet_bytes_min,")?;
        write!(writer, "bidirectional_packet_bytes_mean,")?;
        write!(writer, "bidirectional_packet_bytes_std,")?;

        write!(writer, "forward_packet_bytes_sum,")?;
        write!(writer, "forward_packet_bytes_max,")?;
        write!(writer, "forward_packet_bytes_min,")?;
        write!(writer, "forward_packet_bytes_mean,")?;
        write!(writer, "forward_packet_bytes_std,")?;

        write!(writer, "backward_packet_bytes_sum,")?;
        write!(writer, "backward_packet_bytes_max,")?;
        write!(writer, "backward_packet_bytes_min,")?;
        write!(writer, "backward_packet_bytes_mean,")?;
        write!(writer, "backward_packet_bytes_std,")?;

        write!(writer, "bidirectional_bytes_s,")?;
        write!(writer, "backward_bytes_s,")?;
        write!(writer, "forward_bytes_s,")?;

        write!(writer, "down_up_bytes_ratio,")?;

        Ok(())
    }
    fn write_csv_value<T: ?Sized + std::io::Write>(
        &self,
        writer: &mut BufWriter<T>,
        flow_times: &FlowTimes,
    ) -> Result<(), Error> {
        write!(writer, "{},", self.bidirectional.current_sum())?;
        write!(writer, "{},", self.bidirectional.current_max().unwrap_or(0))?;
        write!(writer, "{},", self.bidirectional.current_min().unwrap_or(0))?;
        write!(writer, "{:.9},", self.bidirectional.current_mean())?;
        write!(
            writer,
            "{:.9},",
            self.bidirectional.current_standard_deviation()
        )?;

        write!(writer, "{},", self.forward.current_sum())?;
        write!(writer, "{},", self.forward.current_max().unwrap_or(0))?;
        write!(writer, "{},", self.forward.current_min().unwrap_or(0))?;
        write!(writer, "{:.9},", self.forward.current_mean())?;
        write!(writer, "{:.9},", self.forward.current_standard_deviation())?;

        write!(writer, "{},", self.backward.current_sum())?;
        write!(writer, "{},", self.backward.current_max().unwrap_or(0))?;
        write!(writer, "{},", self.backward.current_min().unwrap_or(0))?;
        write!(writer, "{:.9},", self.backward.current_mean())?;
        write!(writer, "{:.9},", self.backward.current_standard_deviation())?;

        if flow_times.duration().is_zero() {
            write!(writer, "{},", 0)?;
            write!(writer, "{},", 0)?;
            write!(writer, "{},", 0)?;
        } else {
            let duration = flow_times.duration_seconds_f64();
            write!(
                writer,
                "{:.9},",
                (self.bidirectional.current_sum() as f64) / duration
            )?;
            write!(
                writer,
                "{:.9},",
                (self.forward.current_sum() as f64) / duration
            )?;
            write!(
                writer,
                "{:.9},",
                (self.backward.current_sum() as f64) / duration
            )?;
        }

        write!(
            writer,
            "{:.9},",
            (self.backward.current_sum() as f64) / (self.forward.current_sum() as f64)
        )?;

        Ok(())
    }
}
