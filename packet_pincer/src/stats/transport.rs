use super::{running_stat::RunningStat, FlowStat, FlowTimes};
use crate::{packet_flow::FragmentReasemblyInformation, packet_parse::TransportFlowIdentifier};
use std::{
    io::{BufWriter, Error, Write},
    net::IpAddr,
};

#[derive(Debug)]
pub struct Transport {
    forward_transport_header_bytes: RunningStat,
    forward_transport_payload_bytes: RunningStat,
    backward_transport_header_bytes: RunningStat,
    backward_transport_payload_bytes: RunningStat,

    forward_transport_packets_with_payload_count: u32,

    forward_tcp_initial_window_bytes: u32,
    backward_tcp_initial_window_bytes: Option<u32>,
}

impl FlowStat for Transport {
    fn from_packet(
        _identifier: &TransportFlowIdentifier,
        _flow_times: &FlowTimes,
        _packet_header: &pcap::PacketHeader,
        sliced_packet: &etherparse::SlicedPacket,
        _reasembly_information: Option<&FragmentReasemblyInformation>,
    ) -> Self {
        let mut forward_transport_header_bytes = RunningStat::new();
        let mut forward_transport_payload_bytes = RunningStat::new();
        let mut forward_transport_packets_with_payload_count = 0;
        let mut forward_tcp_initial_window_bytes = 0;

        if let Some(transport_slice) = &sliced_packet.transport {
            match transport_slice {
                etherparse::TransportSlice::Icmpv4(s) => {
                    forward_transport_header_bytes.include(s.header_len().try_into().unwrap());
                    forward_transport_payload_bytes.include(s.payload().len().try_into().unwrap());
                    if !s.payload().is_empty() {
                        forward_transport_packets_with_payload_count = 1
                    }
                }
                etherparse::TransportSlice::Icmpv6(s) => {
                    forward_transport_header_bytes.include(s.header_len().try_into().unwrap());
                    forward_transport_payload_bytes.include(s.payload().len().try_into().unwrap());
                    if !s.payload().is_empty() {
                        forward_transport_packets_with_payload_count = 1
                    }
                }
                etherparse::TransportSlice::Udp(s) => {
                    forward_transport_header_bytes.include(s.header_len().try_into().unwrap());
                    forward_transport_payload_bytes.include(s.payload().len().try_into().unwrap());
                    if !s.payload().is_empty() {
                        forward_transport_packets_with_payload_count = 1
                    }
                }
                etherparse::TransportSlice::Tcp(s) => {
                    forward_transport_header_bytes.include(s.header_len().try_into().unwrap());
                    forward_transport_payload_bytes.include(s.payload().len().try_into().unwrap());
                    if !s.payload().is_empty() {
                        forward_transport_packets_with_payload_count = 1
                    }
                    forward_tcp_initial_window_bytes = s.window_size().into();
                }
            };
        }

        Self {
            forward_transport_header_bytes,
            forward_transport_payload_bytes,
            backward_transport_header_bytes: RunningStat::new(),
            backward_transport_payload_bytes: RunningStat::new(),
            forward_transport_packets_with_payload_count,
            forward_tcp_initial_window_bytes,
            backward_tcp_initial_window_bytes: None,
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
        let is_forward = match &sliced_packet.net {
            Some(header) => match header {
                etherparse::NetSlice::Ipv4(v) => {
                    IpAddr::V4(v.header().source_addr()) == identifier.source_ip
                }
                etherparse::NetSlice::Ipv6(v) => {
                    IpAddr::V6(v.header().source_addr()) == identifier.source_ip
                }
            },
            None => panic!("Unexpected sliced packet without net layer"),
        };

        if let Some(transport_slice) = &sliced_packet.transport {
            match (transport_slice, is_forward) {
                (etherparse::TransportSlice::Icmpv4(s), true) => {
                    self.forward_transport_header_bytes
                        .include(s.header_len().try_into().unwrap());
                    self.forward_transport_payload_bytes
                        .include(s.payload().len().try_into().unwrap());
                    if !s.payload().is_empty() {
                        self.forward_transport_packets_with_payload_count += 1;
                    }
                }
                (etherparse::TransportSlice::Icmpv6(s), true) => {
                    self.forward_transport_header_bytes
                        .include(s.header_len().try_into().unwrap());
                    self.forward_transport_payload_bytes
                        .include(s.payload().len().try_into().unwrap());
                    if !s.payload().is_empty() {
                        self.forward_transport_packets_with_payload_count += 1;
                    }
                }
                (etherparse::TransportSlice::Udp(s), true) => {
                    self.forward_transport_header_bytes
                        .include(s.header_len().try_into().unwrap());
                    self.forward_transport_payload_bytes
                        .include(s.payload().len().try_into().unwrap());
                    if !s.payload().is_empty() {
                        self.forward_transport_packets_with_payload_count += 1;
                    }
                }
                (etherparse::TransportSlice::Tcp(s), true) => {
                    self.forward_transport_header_bytes
                        .include(s.header_len().try_into().unwrap());
                    self.forward_transport_payload_bytes
                        .include(s.payload().len().try_into().unwrap());
                    if !s.payload().is_empty() {
                        self.forward_transport_packets_with_payload_count += 1;
                    }
                }
                (etherparse::TransportSlice::Icmpv4(s), false) => {
                    self.backward_transport_header_bytes
                        .include(s.header_len().try_into().unwrap());
                    self.backward_transport_payload_bytes
                        .include(s.payload().len().try_into().unwrap());
                }
                (etherparse::TransportSlice::Icmpv6(s), false) => {
                    self.backward_transport_header_bytes
                        .include(s.header_len().try_into().unwrap());
                    self.backward_transport_payload_bytes
                        .include(s.payload().len().try_into().unwrap());
                }
                (etherparse::TransportSlice::Udp(s), false) => {
                    self.backward_transport_header_bytes
                        .include(s.header_len().try_into().unwrap());
                    self.backward_transport_payload_bytes
                        .include(s.payload().len().try_into().unwrap());
                }
                (etherparse::TransportSlice::Tcp(s), false) => {
                    self.backward_transport_header_bytes
                        .include(s.header_len().try_into().unwrap());
                    self.backward_transport_payload_bytes
                        .include(s.payload().len().try_into().unwrap());
                    if self.backward_tcp_initial_window_bytes.is_none() {
                        self.backward_tcp_initial_window_bytes = Some(s.window_size().into())
                    }
                }
            }
        }
    }

    fn write_csv_header<T: ?Sized + std::io::Write>(
        writer: &mut BufWriter<T>,
    ) -> Result<(), Error> {
        write!(writer, "forward_transport_header_bytes_sum,")?;
        write!(writer, "forward_transport_payload_bytes_mean,")?;
        write!(writer, "forward_transport_payload_bytes_min,")?;
        write!(writer, "forward_transport_packets_with_payload_count,")?;
        write!(writer, "forward_tcp_initial_window_bytes,")?;
        write!(writer, "backward_transport_header_bytes_sum,")?;
        write!(writer, "backward_transport_payload_bytes_mean,")?;
        write!(writer, "backward_tcp_initial_window_bytes,")?;

        Ok(())
    }

    fn write_csv_value<T: ?Sized + std::io::Write>(
        &self,
        writer: &mut BufWriter<T>,
        _flow_times: &FlowTimes,
    ) -> Result<(), Error> {
        write!(
            writer,
            "{},",
            self.forward_transport_header_bytes.current_sum()
        )?;
        write!(
            writer,
            "{},",
            self.forward_transport_payload_bytes.current_mean()
        )?;
        write!(
            writer,
            "{},",
            self.forward_transport_payload_bytes
                .current_min()
                .unwrap_or(0)
        )?;
        write!(
            writer,
            "{},",
            self.forward_transport_packets_with_payload_count
        )?;
        write!(writer, "{},", self.forward_tcp_initial_window_bytes)?;
        write!(
            writer,
            "{},",
            self.backward_transport_header_bytes.current_sum()
        )?;
        write!(
            writer,
            "{},",
            self.backward_transport_payload_bytes.current_mean()
        )?;
        write!(
            writer,
            "{},",
            self.backward_tcp_initial_window_bytes.unwrap_or(0)
        )?;

        Ok(())
    }
}
