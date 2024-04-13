use std::net::IpAddr;
use etherparse::SlicedPacket;
use etherparse::IpNumber;

use pcap::{Packet, Linktype};

/// Try to parse the given packet in the given link type.
pub fn try_parse_packet<'a>(link_type: Linktype, packet: &'a Packet<'_>) -> Option<SlicedPacket<'a>> {
    match link_type {
        Linktype::ETHERNET => match SlicedPacket::from_ethernet(packet.data) {
            Ok(value) => Some(value),
            Err(_err) => None
        },
        Linktype::LINUX_SLL => None, // TODO: implement sll suport
        _ => None
    }
}

/// An identifier for a comunication between two hosts
#[derive(Debug)]
pub struct FlowIdentifier {
    source_ip: IpAddr,
    source_port: u16,
    dest_ip: IpAddr,
    dest_port: u16,
    transport_protocol: IpNumber,
}

impl FlowIdentifier {
    /// Try to extract the relevant flow identifiers from the sliced packet
    pub fn from_sliced_packet(packet: SlicedPacket) -> Option<FlowIdentifier> {
        let source_ip: IpAddr;
        let source_port: u16;
        let dest_ip: IpAddr;
        let dest_port: u16;
        let transport_protocol: IpNumber;

        match packet.net {
            Some(header) => match header {
                etherparse::NetSlice::Ipv4(v) => {
                    source_ip = IpAddr::V4(v.header().source_addr());
                    dest_ip = IpAddr::V4(v.header().destination_addr());
                    transport_protocol = v.header().protocol();
                }
                etherparse::NetSlice::Ipv6(v) => {
                    source_ip = IpAddr::V6(v.header().source_addr());
                    dest_ip = IpAddr::V6(v.header().destination_addr());
                    transport_protocol = v.header().next_header();
                }
            },
            None => return None
        }

        match packet.transport {
            Some(header) => match header {
                etherparse::TransportSlice::Tcp(header) => {
                    source_port = header.source_port();
                    dest_port = header.destination_port();
                }
                etherparse::TransportSlice::Udp(header) => {
                    source_port = header.source_port();
                    dest_port = header.destination_port();
                }
                _ => return None
            }
            None => return None
        }

        Some(FlowIdentifier{
            source_ip,
            source_port,
            dest_ip,
            dest_port,
            transport_protocol
        })
    }
}