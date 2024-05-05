use super::FlowStat;
use crate::{packet_flow::FragmentReasemblyInformation, packet_parse::TransportFlowIdentifier};
use std::io::{BufWriter, Error, Write};

#[derive(Debug)]
pub struct ByteCount {
    count: u64,
}

impl FlowStat for ByteCount {
    fn from_packet(
        _identifier: &TransportFlowIdentifier,
        packet_header: &pcap::PacketHeader,
        _sliced_packet: &etherparse::SlicedPacket,
        reasembly_information: Option<&FragmentReasemblyInformation>,
    ) -> Self {
        let count = match reasembly_information {
            Some(reasembly_information) => reasembly_information.total_bytes_received_count.into(),
            None => packet_header.len.into(),
        };

        ByteCount { count }
    }
    fn include(
        &mut self,
        _identifier: &TransportFlowIdentifier,
        packet_header: &pcap::PacketHeader,
        _sliced_packet: &etherparse::SlicedPacket,
        reasembly_information: Option<&FragmentReasemblyInformation>,
    ) {
        let count: u64 = match reasembly_information {
            Some(reasembly_information) => reasembly_information.total_bytes_received_count.into(),
            None => packet_header.len.into(),
        };

        self.count += count;
    }
    fn write_csv_header<T: ?Sized + std::io::Write>(
        writer: &mut BufWriter<T>,
    ) -> Result<(), Error> {
        write!(writer, "byte_count")?;
        Ok(())
    }
    fn write_csv_value<T: ?Sized + std::io::Write>(
        &self,
        writer: &mut BufWriter<T>,
    ) -> Result<(), Error> {
        write!(writer, "{}", self.count)?;
        Ok(())
    }
}
