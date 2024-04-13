use std::collections::HashMap;
use chrono::{DateTime, Utc};
use etherparse::SlicedPacket;

use crate::{get_datetime_of_packet, try_parse_packet, FlowIdentifier};

/// The commulative information of the flow of information between two hosts
#[derive(Debug)]
#[allow(dead_code)]
pub struct Flow {
    identifier: FlowIdentifier,
    first_packet_time: DateTime<Utc>,
    last_packet_time: DateTime<Utc>,
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
    pub fn include<'a>(&mut self, packet_header: &pcap::PacketHeader, _sliced_packet: SlicedPacket<'a>) {
        let packet_time = get_datetime_of_packet(packet_header);
        self.last_packet_time =
            packet_time.expect("Packet headers with invalid timestamps are not supported");
    }
}

/// A group of flows
#[derive(Debug)]
pub struct FlowGroup {
    flows: HashMap<FlowIdentifier, Flow>,
}

impl FlowGroup {
    /// Create an empty group of flows
    pub fn new() -> FlowGroup {
        FlowGroup {
            flows: HashMap::new(),
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
                self.flows.insert(
                    flow_identifier,
                    Flow::from(flow_identifier, packet.header, sliced_packet),
                );
            }
            Some(flow) => {
                flow.include(packet.header, sliced_packet);
            }
        }

        return true;
    }
}
