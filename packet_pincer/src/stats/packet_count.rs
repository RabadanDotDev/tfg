use std::io::{BufWriter, Error, Write};

use crate::{packet_flow::FragmentReasemblyInformation, packet_parse::TransportFlowIdentifier};

use super::FlowStat;

#[derive(Debug)]
pub struct PacketCount {
    count: u64,
}

impl FlowStat for PacketCount {
    fn from_packet(
        _identifier: &TransportFlowIdentifier,
        _packet_header: &pcap::PacketHeader,
        _sliced_packet: &etherparse::SlicedPacket,
        reasembly_information: Option<&FragmentReasemblyInformation>,
    ) -> Self {
        let count = match reasembly_information {
            Some(reasembly_information) => {
                reasembly_information.total_fragments_received_count.into()
            }
            None => 1,
        };
        PacketCount { count }
    }
    fn include(
        &mut self,
        _identifier: &TransportFlowIdentifier,
        _packet_header: &pcap::PacketHeader,
        _sliced_packet: &etherparse::SlicedPacket,
        reasembly_information: Option<&FragmentReasemblyInformation>,
    ) {
        let count = match reasembly_information {
            Some(reasembly_information) => reasembly_information.total_bytes_received_count.into(),
            None => 1,
        };

        self.count += count;
    }
    fn write_csv_header<T: ?Sized + std::io::Write>(
        writer: &mut BufWriter<T>,
    ) -> Result<(), Error> {
        write!(writer, "packet_count")?;
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
