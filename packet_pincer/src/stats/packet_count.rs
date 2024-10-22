use std::{
    io::{BufWriter, Error, Write},
    net::IpAddr,
};

use crate::{packet_flow::FragmentReasemblyInformation, packet_parse::TransportFlowIdentifier};

use super::{FlowStat, FlowTimes};

#[derive(Debug)]
pub struct PacketCount {
    forward_count: u32,
    backward_count: u32,
}

pub fn extract_packet_count(reasembly_information: Option<&FragmentReasemblyInformation>) -> u32 {
    match reasembly_information {
        Some(reasembly_information) => reasembly_information.total_fragments_received_count,
        None => 1,
    }
}

impl FlowStat for PacketCount {
    fn from_packet(
        _identifier: &TransportFlowIdentifier,
        _flow_times: &FlowTimes,
        _packet_header: &pcap::PacketHeader,
        _sliced_packet: &etherparse::SlicedPacket,
        reasembly_information: Option<&FragmentReasemblyInformation>,
    ) -> Self {
        PacketCount {
            forward_count: extract_packet_count(reasembly_information),
            backward_count: 0,
        }
    }
    fn include(
        &mut self,
        identifier: &TransportFlowIdentifier,
        _flow_times: &FlowTimes,
        _packet_header: &pcap::PacketHeader,
        sliced_packet: &etherparse::SlicedPacket,
        reasembly_information: Option<&FragmentReasemblyInformation>,
    ) {
        let count = extract_packet_count(reasembly_information);

        let src_ip = match &sliced_packet.net {
            Some(header) => match header {
                etherparse::NetSlice::Ipv4(v) => IpAddr::V4(v.header().source_addr()),
                etherparse::NetSlice::Ipv6(v) => IpAddr::V6(v.header().source_addr()),
            },
            None => panic!("Unexpected sliced packet without net layer"),
        };

        if src_ip == identifier.source_ip {
            self.forward_count += count;
        } else {
            self.backward_count += count;
        }
    }
    fn write_csv_header<T: ?Sized + std::io::Write>(
        writer: &mut BufWriter<T>,
    ) -> Result<(), Error> {
        write!(writer, "bidirectional_packet_count,")?;
        write!(writer, "forward_packet_count,")?;
        write!(writer, "backward_packet_count,")?;
        write!(writer, "bidirectional_packet_second,")?;
        write!(writer, "forward_packet_second,")?;
        write!(writer, "backward_packet_second,")?;
        Ok(())
    }
    fn write_csv_value<T: ?Sized + std::io::Write>(
        &self,
        writer: &mut BufWriter<T>,
        flow_times: &FlowTimes,
    ) -> Result<(), Error> {
        write!(writer, "{},", self.backward_count + self.forward_count)?;
        write!(writer, "{},", self.forward_count)?;
        write!(writer, "{},", self.backward_count)?;

        if flow_times.duration().is_zero() {
            write!(writer, "{},", 0)?;
            write!(writer, "{},", 0)?;
            write!(writer, "{},", 0)?;
        } else {
            let duration = flow_times.duration_seconds_f64();
            write!(
                writer,
                "{:.9},",
                f64::from(self.backward_count + self.forward_count) / duration
            )?;
            write!(writer, "{:.9},", f64::from(self.forward_count) / duration)?;
            write!(writer, "{:.9},", f64::from(self.backward_count) / duration)?;
        }

        Ok(())
    }
}
