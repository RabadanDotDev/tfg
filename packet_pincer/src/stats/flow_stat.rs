use crate::packet_flow::FragmentReasemblyInformation;
use std::io::{BufWriter, Error};

pub trait FlowStat {
    fn from_packet(
        packet_header: &pcap::PacketHeader,
        sliced_packet: &etherparse::SlicedPacket,
        reasembly_information: Option<&FragmentReasemblyInformation>,
    ) -> Self;
    fn include(
        &mut self,
        packet_header: &pcap::PacketHeader,
        sliced_packet: &etherparse::SlicedPacket,
        reasembly_information: Option<&FragmentReasemblyInformation>,
    );
    fn write_csv_header<T: ?Sized + std::io::Write>(writer: &mut BufWriter<T>)
        -> Result<(), Error>;
    fn write_csv_value<T: ?Sized + std::io::Write>(
        &self,
        writer: &mut BufWriter<T>,
    ) -> Result<(), Error>;
}
