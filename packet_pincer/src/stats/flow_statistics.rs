use super::{ByteCount, FlowStat, FlowTimes, PacketCount};
use crate::packet_flow::FragmentReasemblyInformation;
use std::io::{BufWriter, Error, Write};

#[derive(Debug)]
pub struct FlowStatistics {
    pub(crate) flow_times: FlowTimes,
    packet_count: PacketCount,
    byte_count: ByteCount,
}

// TODO: create a macro to autogenerate this.
impl FlowStat for FlowStatistics {
    fn from_packet(
        packet_header: &pcap::PacketHeader,
        sliced_packet: &etherparse::SlicedPacket,
        reasembly_information: Option<&FragmentReasemblyInformation>,
    ) -> Self {
        FlowStatistics {
            flow_times: FlowTimes::from_packet(packet_header, sliced_packet, reasembly_information),
            packet_count: PacketCount::from_packet(
                packet_header,
                sliced_packet,
                reasembly_information,
            ),
            byte_count: ByteCount::from_packet(packet_header, sliced_packet, reasembly_information),
        }
    }
    fn include(
        &mut self,
        packet_header: &pcap::PacketHeader,
        sliced_packet: &etherparse::SlicedPacket,
        reasembly_information: Option<&FragmentReasemblyInformation>,
    ) {
        self.flow_times
            .include(packet_header, sliced_packet, reasembly_information);
        self.packet_count
            .include(packet_header, sliced_packet, reasembly_information);
        self.byte_count
            .include(packet_header, sliced_packet, reasembly_information);
    }
    fn write_csv_header<T: ?Sized + std::io::Write>(
        writer: &mut BufWriter<T>,
    ) -> Result<(), Error> {
        FlowTimes::write_csv_header(writer)?;
        write!(writer, ",")?;
        PacketCount::write_csv_header(writer)?;
        write!(writer, ",")?;
        ByteCount::write_csv_header(writer)?;
        Ok(())
    }
    fn write_csv_value<T: ?Sized + std::io::Write>(
        &self,
        writer: &mut BufWriter<T>,
    ) -> Result<(), Error> {
        self.flow_times.write_csv_value(writer)?;
        write!(writer, ",")?;
        self.packet_count.write_csv_value(writer)?;
        write!(writer, ",")?;
        self.byte_count.write_csv_value(writer)?;
        Ok(())
    }
}
