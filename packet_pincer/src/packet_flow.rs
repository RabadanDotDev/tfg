use crate::{
    flow_statistic::{FlowStat, FlowStatistics},
    packet_parse::{
        self, try_parse_packet, FlowIdentifier, FragmentationInformation, NetworkFlowIdentifier,
        ParseError, TransportFlowIdentifier,
    },
};
use chrono::{DateTime, TimeDelta, Utc};
use priority_queue::PriorityQueue;
use std::{
    cmp::Reverse,
    collections::HashMap,
    io::{BufWriter, Error, Write},
    rc::Rc,
    vec,
};

/// The commulative information of the flow of information between two hosts
#[derive(Debug)]
pub struct TransportFlow {
    pub(crate) identifier: TransportFlowIdentifier,
    pub(crate) statistics: FlowStatistics,
    label: Option<Rc<str>>,
}

impl TransportFlow {
    /// Create a flow from an initial pcap packet header and its sliced contents
    pub fn from(
        identifier: TransportFlowIdentifier,
        packet_header: &pcap::PacketHeader,
        sliced_packet: etherparse::SlicedPacket,
    ) -> TransportFlow {
        let statistics = FlowStatistics::from_packet(packet_header, &sliced_packet);
        let label = None;

        TransportFlow {
            identifier,
            statistics,
            label,
        }
    }

    /// Assign a label to the flow
    pub fn set_label(&mut self, label: Rc<str>) {
        self.label = Some(label);
    }

    /// Accomulate information to the flow with a given pcap packet header and its sliced contents
    pub fn include(
        &mut self,
        packet_header: &pcap::PacketHeader,
        sliced_packet: etherparse::SlicedPacket,
    ) {
        self.statistics.include(packet_header, &sliced_packet);
    }

    /// Write the header for separated information values of the flows to the given writer
    pub fn write_csv_header<T: ?Sized + std::io::Write>(
        writer: &mut BufWriter<T>,
        label_column: bool,
    ) -> Result<(), Error> {
        TransportFlowIdentifier::write_csv_header(writer)?;
        write!(writer, ",")?;
        FlowStatistics::write_csv_header(writer)?;
        if label_column {
            write!(writer, ",")?;
            write!(writer, "label")?;
        }
        writeln!(writer)?;
        Ok(())
    }

    /// Write the coma separated information values of the flow to the given writer
    pub fn write_csv_value<T: ?Sized + std::io::Write>(
        &self,
        writer: &mut BufWriter<T>,
        label_column: bool,
    ) -> Result<(), Error> {
        self.identifier.write_csv_value(writer)?;
        write!(writer, ",")?;
        self.statistics.write_csv_value(writer)?;
        if label_column {
            write!(writer, ",")?;
            match &self.label {
                None => write!(writer, ""),
                Some(v) => write!(writer, "{}", v),
            }?;
        }
        writeln!(writer)?;
        Ok(())
    }
}

/// The fragments on a network flow yet to be reasembled
#[derive(Debug)]
pub struct NetworkFragmentFlow {
    pub(crate) identifier: NetworkFlowIdentifier,
    first_time: DateTime<Utc>,
    last_time: DateTime<Utc>,
    expected_size: Option<usize>,
    fragments_data: Vec<(etherparse::IpFragOffset, Vec<u8>)>, // TODO: change this field to a better data structure
    received_fragment_count: u32, // We track this separately because fragments with equal offset get overriden
}

impl NetworkFragmentFlow {
    /// Create a flow from an initial pcap packet header and its sliced contents
    pub fn from(
        identifier: NetworkFlowIdentifier,
        packet_header: &pcap::PacketHeader,
        sliced_packet: etherparse::SlicedPacket,
        fragmentation_offset: etherparse::IpFragOffset,
        more_packets: bool,
    ) -> NetworkFragmentFlow {
        let time = packet_parse::get_datetime_of_packet(packet_header)
            .expect("Packet headers with invalid timestamps are not supported");
        let ip_payload = sliced_packet.ip_payload().unwrap().payload.to_owned();
        let expected_size = if more_packets {
            None
        } else {
            Some(usize::from(fragmentation_offset.value()) + ip_payload.len())
        };

        NetworkFragmentFlow {
            identifier,
            first_time: time,
            last_time: time,
            expected_size,
            fragments_data: vec![(fragmentation_offset, ip_payload)],
            received_fragment_count: 1,
        }
    }

    /// Accomulate information to the flow with a given pcap packet header and
    /// its sliced contents.
    pub fn include(
        &mut self,
        packet_header: &pcap::PacketHeader,
        sliced_packet: etherparse::SlicedPacket,
        fragmentation_offset: etherparse::IpFragOffset,
        more_packets: bool,
    ) {
        self.last_time = packet_parse::get_datetime_of_packet(packet_header)
            .expect("Packet headers with invalid timestamps are not supported");
        let ip_payload = sliced_packet.ip_payload().unwrap().payload.to_owned();

        if self.expected_size.is_none() && !more_packets {
            self.expected_size = Some(usize::from(fragmentation_offset.value()) + ip_payload.len());
        }

        match self
            .fragments_data
            .binary_search_by_key(&fragmentation_offset, |v| v.0)
        {
            Ok(v) => self.fragments_data[v].1 = ip_payload,
            Err(v) => self
                .fragments_data
                .insert(v, (fragmentation_offset, ip_payload)),
        }

        self.received_fragment_count += 1;
    }
}

/// A group of flows
#[derive(Debug)]
pub struct FlowGroup {
    transport_flows: HashMap<TransportFlowIdentifier, TransportFlow>,
    transport_flows_queue: PriorityQueue<TransportFlowIdentifier, Reverse<DateTime<Utc>>>,
    network_fragment_flows: HashMap<NetworkFlowIdentifier, NetworkFragmentFlow>,
    network_fragment_flows_queue: PriorityQueue<NetworkFlowIdentifier, DateTime<Utc>>,
    latest_time: Option<DateTime<Utc>>,
}

impl FlowGroup {
    /// Create an empty group of flows
    pub fn new() -> FlowGroup {
        FlowGroup {
            transport_flows: HashMap::new(),
            transport_flows_queue: PriorityQueue::new(),
            network_fragment_flows: HashMap::new(),
            network_fragment_flows_queue: PriorityQueue::new(),
            latest_time: None,
        }
    }

    /// Accomulate information to the correct flow given a packet and its
    /// respective link type. On success, returns the number of valid packets
    /// and invalid packets. This will usually be (1, 0), but can differ in
    /// case of fragmented packets. If packets are kept for reeasembly, it will
    /// return (0, 0). If a reassembly happens, it will return the ones that
    /// were used and the ones that were discarded
    pub fn include(
        &mut self,
        link_type: pcap::Linktype,
        packet: &pcap::Packet<'_>,
    ) -> Result<(u32, u32), ParseError> {
        // Record time
        self.latest_time = Some(
            packet_parse::get_datetime_of_packet(packet.header)
                .expect("Packet headers with invalid timestamps are not supported"),
        );

        // Slice packet
        let sliced_packet = try_parse_packet(link_type, packet)?;

        // Extract identification
        let (flow_identifier, fragmentation_information) =
            FlowIdentifier::from_sliced_packet(&sliced_packet)?;

        // Store flow
        match flow_identifier {
            FlowIdentifier::TransportFlowIdentifier(transport_flow_identifier) => {
                self.store_transport_flow(transport_flow_identifier, packet.header, sliced_packet);
                Ok((1, 0))
            }
            FlowIdentifier::NetworkFlowIdentifier(network_flow_identifier) => {
                match fragmentation_information {
                    FragmentationInformation::NoFragmentation => {
                        Err(ParseError::MissingTransportLayer)
                    }
                    FragmentationInformation::ReassembledIPv4Packet => unreachable!(),
                    FragmentationInformation::FragmentedIpv4Packet {
                        fragmentation_offset,
                        more_packets,
                    } => self.evaluate_ipv4_fragment(
                        network_flow_identifier,
                        packet.header,
                        sliced_packet,
                        fragmentation_offset,
                        more_packets,
                    ),
                }
            }
        }
    }

    fn store_transport_flow(
        &mut self,
        transport_flow_identifier: TransportFlowIdentifier,
        packet_header: &pcap::PacketHeader,
        sliced_packet: etherparse::SlicedPacket<'_>,
    ) {
        match self.transport_flows.get_mut(&transport_flow_identifier) {
            None => {
                let flow =
                    TransportFlow::from(transport_flow_identifier, packet_header, sliced_packet);
                self.transport_flows_queue.push(
                    transport_flow_identifier,
                    Reverse(flow.statistics.flow_times.last_packet_time),
                );
                self.transport_flows.insert(transport_flow_identifier, flow);
            }
            Some(flow) => {
                flow.include(packet_header, sliced_packet);
                self.transport_flows_queue.change_priority(
                    &transport_flow_identifier,
                    Reverse(flow.statistics.flow_times.last_packet_time),
                );
            }
        }
    }

    fn evaluate_ipv4_fragment(
        &mut self,
        network_flow_identifier: NetworkFlowIdentifier,
        packet_header: &pcap::PacketHeader,
        sliced_packet: etherparse::SlicedPacket<'_>,
        fragmentation_offset: etherparse::IpFragOffset,
        more_packets: bool,
    ) -> Result<(u32, u32), ParseError> {
        match self
            .network_fragment_flows
            .get_mut(&network_flow_identifier)
        {
            None => {
                let flow = NetworkFragmentFlow::from(
                    network_flow_identifier,
                    packet_header,
                    sliced_packet,
                    fragmentation_offset,
                    more_packets,
                );
                self.network_fragment_flows_queue
                    .push(network_flow_identifier, flow.first_time);
                self.network_fragment_flows
                    .insert(network_flow_identifier, flow);

                Ok((0, 0))
            }
            Some(flow) => {
                flow.include(
                    packet_header,
                    sliced_packet,
                    fragmentation_offset,
                    more_packets,
                );

                // TODO: Try reasemble packet
                Ok((0, 0))
            }
        }
    }

    /// From the transport flow that has been the most time without receiving a
    /// packet, get the timestamp when the last packet was received
    fn get_oldest_time_transport(&self) -> Option<DateTime<Utc>> {
        Some(self.transport_flows_queue.peek()?.1 .0)
    }

    /// Get the first time a fragment was received from the oldest network
    /// fragment flow
    fn get_oldest_time_network_fragment(&self) -> Option<DateTime<Utc>> {
        Some(*self.network_fragment_flows_queue.peek()?.1)
    }

    /// Try popping oldest transport flow if it has passed more time than
    /// `time_delta` between last packet received on it and the last packet in
    /// general
    pub fn pop_oldest_transport_flow_if_older_than(
        &mut self,
        time_delta: TimeDelta,
    ) -> Option<TransportFlow> {
        if let Some((oldest_time, latest_time)) =
            self.get_oldest_time_transport().zip(self.latest_time)
        {
            if time_delta < latest_time - oldest_time {
                let (flow_identifier, _) = self.transport_flows_queue.pop().unwrap();
                let flow = self.transport_flows.remove(&flow_identifier).unwrap();
                Some(flow)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Try popping oldest transport flow
    pub fn pop_oldest_transport_flow(&mut self) -> Option<TransportFlow> {
        if let Some((flow_identifier, _)) = self.transport_flows_queue.pop() {
            let flow = self.transport_flows.remove(&flow_identifier).unwrap();
            Some(flow)
        } else {
            None
        }
    }

    /// Try popping oldest network flow fragment if it has passed more time
    /// than `time_delta` between the first packet received on it and the last
    /// packet in general. In success, returns the number of fragments received
    /// on the flow that were accomulated but not reasembled
    pub fn pop_oldest_network_flow_if_older_than(&mut self, time_delta: TimeDelta) -> Option<u32> {
        if let Some((oldest_time, latest_time)) = self
            .get_oldest_time_network_fragment()
            .zip(self.latest_time)
        {
            if time_delta < latest_time - oldest_time {
                let (network_flow_identifier, _) = self.network_fragment_flows_queue.pop().unwrap();
                let flow = self
                    .network_fragment_flows
                    .remove(&network_flow_identifier)
                    .unwrap();
                Some(flow.received_fragment_count)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Try popping oldest network flow. In success, returns the number of
    /// fragments received on the flow that were accomulated but not reasembled
    pub fn pop_oldest_network_flow(&mut self) -> Option<u32> {
        if let Some((network_flow_identifier, _)) = self.network_fragment_flows_queue.pop() {
            let flow = self
                .network_fragment_flows
                .remove(&network_flow_identifier)
                .unwrap();
            Some(flow.received_fragment_count)
        } else {
            None
        }
    }
}

impl Default for FlowGroup {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use etherparse::{IpNumber, PacketBuilder};
    use libc::timeval;

    use super::*;
    #[test]
    #[rustfmt::skip]
    fn test_correct_transport_flow_order_inclusion() {
        // Create flow group
        let mut flow_group = FlowGroup::new();

        assert_eq!(flow_group.latest_time, None);

        // Common packet data
        let link_type = pcap::Linktype::ETHERNET;
        let payload = [1, 2, 3, 4, 5, 6, 7, 8];

        // First packet
        {
            // Create
            let flow_identifier = TransportFlowIdentifier::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                21,
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
                1234,
                IpNumber::UDP,
            );

            let origin = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
                .ipv4([192, 168, 1, 1], [192, 168, 1, 2], 20)
                .udp(21, 1234);

            let mut packet_payload = Vec::<u8>::with_capacity(origin.size(payload.len()));
            origin.write(&mut packet_payload, &payload).unwrap();
            let packet_1 = pcap::Packet {
                header: &pcap::PacketHeader {
                    ts: timeval {
                        tv_sec: 0,
                        tv_usec: 0,
                    },
                    caplen: packet_payload.len().try_into().unwrap(),
                    len: packet_payload.len().try_into().unwrap(),
                },
                data: &packet_payload,
            };

            // Include first packet on the group
            let _ = flow_group.include(link_type, &packet_1);

            // Assert
            assert_eq!(flow_group.transport_flows.len(), 1);
            assert_eq!(flow_group.transport_flows_queue.len(), 1);
            assert!(flow_group.transport_flows.contains_key(&flow_identifier));
            assert_eq!(
                flow_group.transport_flows_queue.peek().unwrap().0,
                &flow_identifier
            );
            assert_eq!(flow_group.get_oldest_time_transport().unwrap().timestamp(), 0);
            assert_eq!(flow_group.get_oldest_time_transport().unwrap().timestamp_micros(), 0);
            assert_eq!(flow_group.latest_time.unwrap().timestamp(), 0);
            assert_eq!(flow_group.latest_time.unwrap().timestamp_micros(), 0);
        }

        // Try popping
        assert!(flow_group
            .pop_oldest_transport_flow_if_older_than(TimeDelta::microseconds(3))
            .is_none());

        // Second packet

        // Create
        let flow_identifier_second = TransportFlowIdentifier::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            1234,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            21,
            IpNumber::UDP,
        );

        {
            let origin = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
                .ipv4([192, 168, 1, 2], [192, 168, 1, 1], 20)
                .udp(1234, 21);

            let mut packet_payload = Vec::<u8>::with_capacity(origin.size(payload.len()));
            origin.write(&mut packet_payload, &payload).unwrap();
            let packet_1 = pcap::Packet {
                header: &pcap::PacketHeader {
                    ts: timeval {
                        tv_sec: 0,
                        tv_usec: 1,
                    },
                    caplen: packet_payload.len().try_into().unwrap(),
                    len: packet_payload.len().try_into().unwrap(),
                },
                data: &packet_payload,
            };

            // Include first packet on the group
            let _ = flow_group.include(link_type, &packet_1);

            // Assert
            assert_eq!(flow_group.transport_flows.len(), 1);
            assert_eq!(flow_group.transport_flows_queue.len(), 1);
            assert!(flow_group
                .transport_flows
                .contains_key(&flow_identifier_second));
            assert_eq!(
                flow_group.transport_flows_queue.peek().unwrap().0,
                &flow_identifier_second
            );
            assert_eq!(flow_group.get_oldest_time_transport().unwrap().timestamp(), 0);
            assert_eq!(flow_group.get_oldest_time_transport().unwrap().timestamp_micros(), 1);
            assert_eq!(flow_group.latest_time.unwrap().timestamp(), 0);
            assert_eq!(flow_group.latest_time.unwrap().timestamp_micros(), 1);
        }

        // Try popping
        assert!(flow_group
            .pop_oldest_transport_flow_if_older_than(TimeDelta::microseconds(3))
            .is_none());

        // Third packet
        {
            // Create
            let flow_identifier = TransportFlowIdentifier::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3)),
                21,
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4)),
                1234,
                IpNumber::UDP,
            );

            let origin = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
                .ipv4([192, 168, 1, 3], [192, 168, 1, 4], 20)
                .udp(21, 1234);

            let mut packet_payload = Vec::<u8>::with_capacity(origin.size(payload.len()));
            origin.write(&mut packet_payload, &payload).unwrap();
            let packet_1 = pcap::Packet {
                header: &pcap::PacketHeader {
                    ts: timeval {
                        tv_sec: 0,
                        tv_usec: 10,
                    },
                    caplen: packet_payload.len().try_into().unwrap(),
                    len: packet_payload.len().try_into().unwrap(),
                },
                data: &packet_payload,
            };

            // Include first packet on the group
            let _ = flow_group.include(link_type, &packet_1);

            // Assert
            assert_eq!(flow_group.transport_flows.len(), 2);
            assert_eq!(flow_group.transport_flows_queue.len(), 2);
            assert!(flow_group.transport_flows.contains_key(&flow_identifier));
            assert_eq!(
                flow_group.transport_flows_queue.peek().unwrap().0,
                &flow_identifier_second
            );
            assert_eq!(flow_group.get_oldest_time_transport().unwrap().timestamp(), 0);
            assert_eq!(flow_group.get_oldest_time_transport().unwrap().timestamp_micros(), 1);
            assert_eq!(flow_group.latest_time.unwrap().timestamp(), 0);
            assert_eq!(flow_group.latest_time.unwrap().timestamp_micros(), 10);
        }

        // Try popping
        assert!(flow_group
            .pop_oldest_transport_flow_if_older_than(TimeDelta::microseconds(3))
            .is_some());
    }
}
