use super::{ByteCount, FlowStat, FlowTimes, PacketCount, Protocols};
use crate::packet_flow::FragmentReasemblyInformation;
use std::io::Write;

macro_rules! impl_flow_stat {
    ($struct_name:ident { $($field:ident : $field_type:ty),* $(,)? }) => {
        impl FlowStat for $struct_name {
            fn from_packet(
                packet_header: &pcap::PacketHeader,
                sliced_packet: &etherparse::SlicedPacket,
                reasembly_information: Option<&FragmentReasemblyInformation>,
            ) -> Self {
                $struct_name {
                    $(
                        $field: <$field_type>::from_packet(packet_header, sliced_packet, reasembly_information),
                    )*
                }
            }

            fn include(
                &mut self,
                packet_header: &pcap::PacketHeader,
                sliced_packet: &etherparse::SlicedPacket,
                reasembly_information: Option<&FragmentReasemblyInformation>,
            ) {
                $(
                    self.$field.include(packet_header, sliced_packet, reasembly_information);
                )*
            }

            fn write_csv_header<T: ?Sized + std::io::Write>(
                writer: &mut std::io::BufWriter<T>,
            ) -> Result<(), std::io::Error> {
                // TODO: avoid writing the last ","
                $(
                    <$field_type>::write_csv_header(writer)?;
                    write!(writer, ",")?;
                )*
                Ok(())
            }

            fn write_csv_value<T: ?Sized + std::io::Write>(
                &self,
                writer: &mut std::io::BufWriter<T>,
            ) -> Result<(), std::io::Error> {
                // TODO: avoid writing the last ","
                $(
                    self.$field.write_csv_value(writer)?;
                    write!(writer, ",")?;
                )*
                Ok(())
            }
        }
    };
}


#[derive(Debug)]
pub struct FlowStatistics {
    pub(crate) flow_times: FlowTimes,
    protocols: Protocols,
    packet_count: PacketCount,
    byte_count: ByteCount,
}

impl_flow_stat!(FlowStatistics {
    flow_times: FlowTimes,
    protocols: Protocols,
    packet_count: PacketCount,
    byte_count: ByteCount,
});
