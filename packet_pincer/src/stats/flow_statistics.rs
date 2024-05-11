use super::interarrival::Interarrival;
use super::{ByteCount, FlowStat, FlowTimes, PacketCount, Protocols, TcpFlags};
use crate::packet_flow::FragmentReasemblyInformation;
use crate::packet_parse::TransportFlowIdentifier;

macro_rules! impl_flow_stat {
    ($struct_name:ident { $($field:ident : $field_type:ty),* $(,)? }) => {
        impl FlowStat for $struct_name {
            fn from_packet(
                identifier: &TransportFlowIdentifier,
                flow_times: &FlowTimes,
                packet_header: &pcap::PacketHeader,
                sliced_packet: &etherparse::SlicedPacket,
                reasembly_information: Option<&FragmentReasemblyInformation>,
            ) -> Self {
                $struct_name {
                    $(
                        $field: <$field_type>::from_packet(identifier, flow_times, packet_header, sliced_packet, reasembly_information),
                    )*
                }
            }

            fn include(
                &mut self,
                identifier: &TransportFlowIdentifier,
                flow_times: &FlowTimes,
                packet_header: &pcap::PacketHeader,
                sliced_packet: &etherparse::SlicedPacket,
                reasembly_information: Option<&FragmentReasemblyInformation>,
            ) {
                $(
                    self.$field.include(identifier, flow_times, packet_header, sliced_packet, reasembly_information);
                )*
            }

            fn write_csv_header<T: ?Sized + std::io::Write>(
                writer: &mut std::io::BufWriter<T>
            ) -> Result<(), std::io::Error> {
                $(
                    <$field_type>::write_csv_header(writer)?;
                )*
                Ok(())
            }

            fn write_csv_value<T: ?Sized + std::io::Write>(
                &self,
                writer: &mut std::io::BufWriter<T>,
                flow_times: &FlowTimes,
            ) -> Result<(), std::io::Error> {
                $(
                    self.$field.write_csv_value(writer, flow_times)?;
                )*
                Ok(())
            }
        }
    };
}

#[derive(Debug)]
pub struct FlowStatistics {
    protocols: Protocols,
    packet_count: PacketCount,
    byte_count: ByteCount,
    interrarival: Interarrival,
    tcp_flags: TcpFlags,
}

impl_flow_stat!(FlowStatistics {
    protocols: Protocols,
    packet_count: PacketCount,
    byte_count: ByteCount,
    interrarival: Interarrival,
    tcp_flags: TcpFlags,
});
