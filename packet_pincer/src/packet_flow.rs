use crate::{
    flow_statistic::{FlowStat, FlowStatistics},
    packet_parse::{try_parse_packet, FlowIdentifier, ParseError, TransportFlowIdentifier},
};
use chrono::{DateTime, TimeDelta, Utc};
use priority_queue::PriorityQueue;
use std::{
    cmp::Reverse,
    collections::HashMap,
    io::{BufWriter, Error, Write},
    rc::Rc,
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

/// A group of flows
#[derive(Debug)]
pub struct FlowGroup {
    transport_flows: HashMap<TransportFlowIdentifier, TransportFlow>,
    transport_flows_queue: PriorityQueue<TransportFlowIdentifier, Reverse<DateTime<Utc>>>,
    latest_time: Option<DateTime<Utc>>,
}

impl FlowGroup {
    /// Create an empty group of flows
    pub fn new() -> FlowGroup {
        FlowGroup {
            transport_flows: HashMap::new(),
            transport_flows_queue: PriorityQueue::new(),
            latest_time: None,
        }
    }

    /// Accomulate information to the correct flow given a packet and its respective link type
    pub fn include(
        &mut self,
        link_type: pcap::Linktype,
        packet: &pcap::Packet<'_>,
    ) -> Result<(), ParseError> {
        // Slice packet
        let sliced_packet = try_parse_packet(link_type, packet)?;

        // Extract identification
        let (flow_identifier, _fragmentation_information) =
            FlowIdentifier::from_sliced_packet(&sliced_packet)?;

        // Store flow
        match flow_identifier {
            FlowIdentifier::TransportFlowIdentifier(transport_flow_identifier) => {
                match self.transport_flows.get_mut(&transport_flow_identifier) {
                    None => {
                        let flow = TransportFlow::from(
                            transport_flow_identifier,
                            packet.header,
                            sliced_packet,
                        );
                        self.transport_flows_queue.push(
                            transport_flow_identifier,
                            Reverse(flow.statistics.flow_times.last_packet_time),
                        );
                        self.transport_flows.insert(transport_flow_identifier, flow);
                    }
                    Some(flow) => {
                        flow.include(packet.header, sliced_packet);
                        self.transport_flows_queue.change_priority(
                            &transport_flow_identifier,
                            Reverse(flow.statistics.flow_times.last_packet_time),
                        );
                    }
                }
            }
            FlowIdentifier::NetworkFlowIdentifier(_) => {
                return Err(ParseError::MissingTransportLayer)
            } // TODO try reassemble packet/store it if its fragmented
        }

        Ok(())
    }

    /// From the flow that has been the most time without receiving a packet,
    /// get the timestamp when the last packet was received
    pub fn get_oldest_time(&self) -> Option<DateTime<Utc>> {
        Some(self.transport_flows_queue.peek()?.1 .0)
    }

    /// Try popping oldest flow if it has passed more time than `time_delta`
    /// between last packet received on it and the last packet in general
    pub fn pop_oldest_flow_if_older_than(
        &mut self,
        time_delta: TimeDelta,
    ) -> Option<TransportFlow> {
        if let Some((oldest_time, latest_time)) = self.get_oldest_time().zip(self.latest_time) {
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

    /// Try popping oldest flow
    pub fn pop_oldest_flow(&mut self) -> Option<TransportFlow> {
        if let Some((flow_identifier, _)) = self.transport_flows_queue.pop() {
            let flow = self.transport_flows.remove(&flow_identifier).unwrap();
            Some(flow)
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
            assert_eq!(flow_group.get_oldest_time().unwrap().timestamp(), 0);
            assert_eq!(flow_group.get_oldest_time().unwrap().timestamp_micros(), 0);
            assert_eq!(flow_group.latest_time.unwrap().timestamp(), 0);
            assert_eq!(flow_group.latest_time.unwrap().timestamp_micros(), 0);
        }

        // Try popping
        assert!(flow_group
            .pop_oldest_flow_if_older_than(TimeDelta::microseconds(3))
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
            assert_eq!(flow_group.get_oldest_time().unwrap().timestamp(), 0);
            assert_eq!(flow_group.get_oldest_time().unwrap().timestamp_micros(), 1);
            assert_eq!(flow_group.latest_time.unwrap().timestamp(), 0);
            assert_eq!(flow_group.latest_time.unwrap().timestamp_micros(), 1);
        }

        // Try popping
        assert!(flow_group
            .pop_oldest_flow_if_older_than(TimeDelta::microseconds(3))
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
            assert_eq!(flow_group.get_oldest_time().unwrap().timestamp(), 0);
            assert_eq!(flow_group.get_oldest_time().unwrap().timestamp_micros(), 1);
            assert_eq!(flow_group.latest_time.unwrap().timestamp(), 0);
            assert_eq!(flow_group.latest_time.unwrap().timestamp_micros(), 10);
        }

        // Try popping
        assert!(flow_group
            .pop_oldest_flow_if_older_than(TimeDelta::microseconds(3))
            .is_some());
    }
}
