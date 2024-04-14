use chrono::{DateTime, TimeDelta, Utc};
use etherparse::SlicedPacket;
use priority_queue::PriorityQueue;
use std::{cmp::Reverse, collections::HashMap};

use crate::{get_datetime_of_packet, try_parse_packet, FlowIdentifier};

/// The commulative information of the flow of information between two hosts
#[derive(Debug)]
#[allow(dead_code)]
pub struct Flow {
    pub identifier: FlowIdentifier,
    pub first_packet_time: DateTime<Utc>,
    pub last_packet_time: DateTime<Utc>,
}

impl Flow {
    /// Create a flow from an initial pcap packet header and its sliced contents
    pub fn from<'a>(
        identifier: FlowIdentifier,
        packet_header: &pcap::PacketHeader,
        _sliced_packet: SlicedPacket<'a>,
    ) -> Flow {
        let packet_time = get_datetime_of_packet(packet_header)
            .expect("Packet headers with invalid timestamps are not supported");

        Flow {
            identifier,
            first_packet_time: packet_time,
            last_packet_time: packet_time,
        }
    }

    /// Accomulate information to the flow with a given pcap packet header and its sliced contents
    pub fn include<'a>(
        &mut self,
        packet_header: &pcap::PacketHeader,
        _sliced_packet: SlicedPacket<'a>,
    ) {
        let packet_time = get_datetime_of_packet(packet_header);
        self.last_packet_time =
            packet_time.expect("Packet headers with invalid timestamps are not supported");
    }
}

/// A group of flows
#[derive(Debug)]
pub struct FlowGroup {
    flows: HashMap<FlowIdentifier, Flow>,
    flows_queue: PriorityQueue<FlowIdentifier, Reverse<DateTime<Utc>>>,
    latest_time: Option<DateTime<Utc>>
}

impl FlowGroup {
    /// Create an empty group of flows
    pub fn new() -> FlowGroup {
        FlowGroup {
            flows: HashMap::new(),
            flows_queue: PriorityQueue::new(),
            latest_time: None
        }
    }

    /// Accomulate information to the correct flow given a packet and its respective link type
    pub fn include<'a>(&mut self, link_type: pcap::Linktype, packet: &pcap::Packet<'_>) -> bool {
        // Slice packet
        let sliced_packet = match try_parse_packet(link_type, packet) {
            Some(sliced_packet) => sliced_packet,
            None => return false,
        };

        // Extract identification
        let flow_identifier = match FlowIdentifier::from_sliced_packet(&sliced_packet) {
            Some(flow_identifier) => flow_identifier,
            None => return false,
        };

        // Store flow
        match self.flows.get_mut(&flow_identifier) {
            None => {
                let flow = Flow::from(flow_identifier, packet.header, sliced_packet);
                self.flows_queue
                    .push(flow_identifier, Reverse(flow.last_packet_time));
                self.latest_time = Some(flow.last_packet_time);
                self.flows.insert(flow_identifier, flow);
            }
            Some(flow) => {
                flow.include(packet.header, sliced_packet);
                self.flows_queue
                    .change_priority(&flow_identifier, Reverse(flow.last_packet_time));
                self.latest_time = Some(flow.last_packet_time);
            }
        }

        return true;
    }

    /// From the flow that has been the most time without receiving a packet, 
    /// get the timestamp when the last packet was received
    pub fn get_oldest_time(&self) -> Option<DateTime<Utc>> {
        Some(self.flows_queue.peek()?.1.0)
    }

    /// Try popping oldest flow if it has passed more time than `time_delta` 
    /// between last packet received on it and the last packet in general
    pub fn pop_oldest_flow_if_older_than(&mut self, time_delta: TimeDelta) -> Option<Flow> {
        if let Some((oldest_time, latest_time)) = self.get_oldest_time().zip(self.latest_time) {
            if time_delta < latest_time - oldest_time {
                let (flow_identifier, _) = self.flows_queue.pop().unwrap();
                let flow = self.flows.remove(&flow_identifier).unwrap();
                return Some(flow);
            } else {
                return None;
            }
        } else {
            return None;
        }
    }

    /// Try popping oldest flow
    pub fn pop_oldest_flow(&mut self) -> Option<Flow> {
        if let Some((flow_identifier, _)) = self.flows_queue.pop() {
            let flow = self.flows.remove(&flow_identifier).unwrap();
            return Some(flow);
        } else {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use etherparse::{IpNumber, PacketBuilder};
    use libc::timeval;

    use super::*;
    #[test]
    fn test_correct_order_inclusion() {
        // Create flow group
        let mut flow_group = FlowGroup::new();

        assert_eq!(flow_group.latest_time, None);

        // Common packet data
        let link_type = pcap::Linktype::ETHERNET;
        let payload = [1,2,3,4,5,6,7,8];

        // First packet
        {
            // Create
            let flow_identifier = FlowIdentifier::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                21,
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
                1234,
                IpNumber::UDP
            );

            let origin = 
                PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
                .ipv4([192, 168, 1, 1], [192, 168, 1, 2], 20)
                .udp(21, 1234);

            let mut packet_payload = Vec::<u8>::with_capacity(origin.size(payload.len()));
            origin.write(&mut packet_payload, &payload).unwrap();
            let packet_1 = pcap::Packet{
                header: &pcap::PacketHeader {
                    ts: timeval {
                        tv_sec: 0,
                        tv_usec: 0
                    },
                    caplen: packet_payload.len().try_into().unwrap(),
                    len: packet_payload.len().try_into().unwrap()
                },
                data: &packet_payload
            };

            // Include first packet on the group
            flow_group.include(link_type, &packet_1);

            // Assert
            assert_eq!(flow_group.flows.len(), 1);
            assert_eq!(flow_group.flows_queue.len(), 1);
            assert!(flow_group.flows.contains_key(&flow_identifier));
            assert_eq!(flow_group.flows_queue.peek().unwrap().0, &flow_identifier);
            assert_eq!(flow_group.get_oldest_time().unwrap().timestamp(), 0);
            assert_eq!(flow_group.get_oldest_time().unwrap().timestamp_micros(), 0);
            assert_eq!(flow_group.latest_time.unwrap().timestamp(), 0);
            assert_eq!(flow_group.latest_time.unwrap().timestamp_micros(), 0);
        }

        // Try popping
        assert!(flow_group.pop_oldest_flow_if_older_than(TimeDelta::microseconds(3)).is_none());

        // Second packet

        // Create
        let flow_identifier_second = FlowIdentifier::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            1234,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            21,
            IpNumber::UDP
        );

        {
            let origin = 
                PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
                .ipv4([192, 168, 1, 2], [192, 168, 1, 1], 20)
                .udp(1234, 21);

            let mut packet_payload = Vec::<u8>::with_capacity(origin.size(payload.len()));
            origin.write(&mut packet_payload, &payload).unwrap();
            let packet_1 = pcap::Packet{
                header: &pcap::PacketHeader {
                    ts: timeval {
                        tv_sec: 0,
                        tv_usec: 1
                    },
                    caplen: packet_payload.len().try_into().unwrap(),
                    len: packet_payload.len().try_into().unwrap()
                },
                data: &packet_payload
            };

            // Include first packet on the group
            flow_group.include(link_type, &packet_1);

            // Assert
            assert_eq!(flow_group.flows.len(), 1);
            assert_eq!(flow_group.flows_queue.len(), 1);
            assert!(flow_group.flows.contains_key(&flow_identifier_second));
            assert_eq!(flow_group.flows_queue.peek().unwrap().0, &flow_identifier_second);
            assert_eq!(flow_group.get_oldest_time().unwrap().timestamp(), 0);
            assert_eq!(flow_group.get_oldest_time().unwrap().timestamp_micros(), 1);
            assert_eq!(flow_group.latest_time.unwrap().timestamp(), 0);
            assert_eq!(flow_group.latest_time.unwrap().timestamp_micros(), 1);
        }

        // Try popping
        assert!(flow_group.pop_oldest_flow_if_older_than(TimeDelta::microseconds(3)).is_none());

        // Third packet
        {
            // Create
            let flow_identifier = FlowIdentifier::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3)),
                21,
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4)),
                1234,
                IpNumber::UDP
            );

            let origin = 
                PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
                .ipv4([192, 168, 1, 3], [192, 168, 1, 4], 20)
                .udp(21, 1234);

            let mut packet_payload = Vec::<u8>::with_capacity(origin.size(payload.len()));
            origin.write(&mut packet_payload, &payload).unwrap();
            let packet_1 = pcap::Packet{
                header: &pcap::PacketHeader {
                    ts: timeval {
                        tv_sec: 0,
                        tv_usec: 10
                    },
                    caplen: packet_payload.len().try_into().unwrap(),
                    len: packet_payload.len().try_into().unwrap()
                },
                data: &packet_payload
            };

            // Include first packet on the group
            flow_group.include(link_type, &packet_1);

            // Assert
            assert_eq!(flow_group.flows.len(), 2);
            assert_eq!(flow_group.flows_queue.len(), 2);
            assert!(flow_group.flows.contains_key(&flow_identifier));
            assert_eq!(flow_group.flows_queue.peek().unwrap().0, &flow_identifier_second);
            assert_eq!(flow_group.get_oldest_time().unwrap().timestamp(), 0);
            assert_eq!(flow_group.get_oldest_time().unwrap().timestamp_micros(), 1);
            assert_eq!(flow_group.latest_time.unwrap().timestamp(), 0);
            assert_eq!(flow_group.latest_time.unwrap().timestamp_micros(), 10);
        }

        // Try popping
        assert!(flow_group.pop_oldest_flow_if_older_than(TimeDelta::microseconds(3)).is_some());
    }
}
