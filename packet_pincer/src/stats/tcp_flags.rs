use super::{FlowStat, FlowTimes};
use crate::{packet_flow::FragmentReasemblyInformation, packet_parse::TransportFlowIdentifier};
use std::{
    io::{BufWriter, Error, Write},
    net::IpAddr,
};

#[derive(Debug, Default)]
pub struct TcpFlags {
    bidirectional_tcp_cwr_flags_count : u32,
    bidirectional_tcp_ece_flags_count : u32,
    bidirectional_tcp_urg_flags_count : u32,
    bidirectional_tcp_ack_flags_count : u32,
    bidirectional_tcp_psh_flags_count : u32,
    bidirectional_tcp_rst_flags_count : u32,
    bidirectional_tcp_syn_flags_count : u32,
    bidirectional_tcp_fin_flags_count : u32,
    forward_tcp_psh_flags_count : u32,
    forward_tcp_urg_flags_count : u32,
    backward_tcp_psh_flags_count : u32,
    backward_tcp_urg_flags_count : u32,
}

impl FlowStat for TcpFlags {
    fn from_packet(
        _identifier: &TransportFlowIdentifier,
        _flow_times: &FlowTimes,
        _packet_header: &pcap::PacketHeader,
        sliced_packet: &etherparse::SlicedPacket,
        _reasembly_information: Option<&FragmentReasemblyInformation>,
    ) -> Self {
        match &sliced_packet.transport {
            Some(etherparse::TransportSlice::Tcp(transport_slice)) => {
                TcpFlags {
                    bidirectional_tcp_cwr_flags_count: if transport_slice.cwr() {1} else {0},
                    bidirectional_tcp_ece_flags_count: if transport_slice.ece() {1} else {0},
                    bidirectional_tcp_urg_flags_count: if transport_slice.urg() {1} else {0},
                    bidirectional_tcp_ack_flags_count: if transport_slice.ack() {1} else {0},
                    bidirectional_tcp_psh_flags_count: if transport_slice.psh() {1} else {0},
                    bidirectional_tcp_rst_flags_count: if transport_slice.rst() {1} else {0},
                    bidirectional_tcp_syn_flags_count: if transport_slice.syn() {1} else {0},
                    bidirectional_tcp_fin_flags_count: if transport_slice.fin() {1} else {0},
                    forward_tcp_psh_flags_count: if transport_slice.psh() {1} else {0},
                    forward_tcp_urg_flags_count: if transport_slice.urg() {1} else {0},
                    backward_tcp_psh_flags_count: 0,
                    backward_tcp_urg_flags_count: 0,
                }
            }
            _ => TcpFlags::default()
        }
    }

    fn include(
        &mut self,
        identifier: &TransportFlowIdentifier,
        _flow_times: &FlowTimes,
        _packet_header: &pcap::PacketHeader,
        sliced_packet: &etherparse::SlicedPacket,
        _reasembly_information: Option<&FragmentReasemblyInformation>,
    ) {
        match &sliced_packet.transport {
            Some(etherparse::TransportSlice::Tcp(transport_slice)) => {
                let src_ip = match &sliced_packet.net {
                    Some(header) => match header {
                        etherparse::NetSlice::Ipv4(v) => IpAddr::V4(v.header().source_addr()),
                        etherparse::NetSlice::Ipv6(v) => IpAddr::V6(v.header().source_addr()),
                    },
                    None => panic!("Unexpected sliced packet without net layer"),
                };
                
                if transport_slice.cwr() {
                    self.bidirectional_tcp_cwr_flags_count += 1;
                }
                if transport_slice.ece() {
                    self.bidirectional_tcp_ece_flags_count += 1;
                }
                if transport_slice.urg() {
                    self.bidirectional_tcp_urg_flags_count += 1;
                }
                if transport_slice.ack() {
                    self.bidirectional_tcp_ack_flags_count += 1;
                }
                if transport_slice.psh() {
                    self.bidirectional_tcp_psh_flags_count += 1;
                }
                if transport_slice.rst() {
                    self.bidirectional_tcp_rst_flags_count += 1;
                }
                if transport_slice.syn() {
                    self.bidirectional_tcp_syn_flags_count += 1;
                }
                if transport_slice.fin() {
                    self.bidirectional_tcp_fin_flags_count += 1;
                }


                if src_ip == identifier.source_ip {
                    self.forward_tcp_psh_flags_count += 1;
                    self.forward_tcp_urg_flags_count += 1;
                } else {
                    self.backward_tcp_urg_flags_count += 1;
                    self.backward_tcp_psh_flags_count += 1;
                }
            }
            _ => {}
        }
    }

    fn write_csv_header<T: ?Sized + std::io::Write>(
        writer: &mut BufWriter<T>,
    ) -> Result<(), Error> {
        write!(writer, "bidirectional_tcp_cwr_flags_count,")?;
        write!(writer, "bidirectional_tcp_ece_flags_count,")?;
        write!(writer, "bidirectional_tcp_urg_flags_count,")?;
        write!(writer, "bidirectional_tcp_ack_flags_count,")?;
        write!(writer, "bidirectional_tcp_psh_flags_count,")?;
        write!(writer, "bidirectional_tcp_rst_flags_count,")?;
        write!(writer, "bidirectional_tcp_syn_flags_count,")?;
        write!(writer, "bidirectional_tcp_fin_flags_count,")?;
        write!(writer, "forward_tcp_psh_flags_count,")?;
        write!(writer, "forward_tcp_urg_flags_count,")?;
        write!(writer, "backward_tcp_psh_flags_count,")?;
        write!(writer, "backward_tcp_urg_flags_count,")?;

        Ok(())
    }

    fn write_csv_value<T: ?Sized + std::io::Write>(
        &self,
        writer: &mut BufWriter<T>,
        _flow_times: &FlowTimes,
    ) -> Result<(), Error> {
        write!(writer, "{},", self.bidirectional_tcp_cwr_flags_count)?;
        write!(writer, "{},", self.bidirectional_tcp_ece_flags_count)?;
        write!(writer, "{},", self.bidirectional_tcp_urg_flags_count)?;
        write!(writer, "{},", self.bidirectional_tcp_ack_flags_count)?;
        write!(writer, "{},", self.bidirectional_tcp_psh_flags_count)?;
        write!(writer, "{},", self.bidirectional_tcp_rst_flags_count)?;
        write!(writer, "{},", self.bidirectional_tcp_syn_flags_count)?;
        write!(writer, "{},", self.bidirectional_tcp_fin_flags_count)?;
        write!(writer, "{},", self.forward_tcp_psh_flags_count)?;
        write!(writer, "{},", self.forward_tcp_urg_flags_count)?;
        write!(writer, "{},", self.backward_tcp_psh_flags_count)?;
        write!(writer, "{},", self.backward_tcp_urg_flags_count)?;

        Ok(())
    }
}
