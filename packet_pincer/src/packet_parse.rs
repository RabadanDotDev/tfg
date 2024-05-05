use chrono::DateTime;
use chrono::Utc;
use etherparse::err::packet::SliceError;
use etherparse::IpNumber;
use std::hash::{Hash, Hasher};
use std::io::{BufWriter, Error, Write};
use std::net::IpAddr;

use pcap::PacketHeader;
use pcap::{Linktype, Packet};

/// Error when trying to parse a packet
#[derive(Debug)]
pub enum ParseError {
    /// Tried to parse a packet with an unsupported link type
    UnsupportedLinkType,
    /// etherparse encounered an error while parsing the packet
    ErrorOnSlicingPacket(SliceError),
    /// etherparse encountered an error while parsing a reassembled packet
    ErrorOnSlicingReassembledPacket {
        /// Slicing error
        error: SliceError,
        /// Number of fragmented packets that were considered
        invalid_fragments: u32,
    },
    /// Could not find the network packet when it was expected
    MissingNetworkLayer,
    /// Could not find the transport layer when it was expected
    MissingTransportLayer,
    /// Tried to parse a packet with an unsupported transport layer
    UnsupportedTransportLayer,
}

/// Indication about the fragmentation status of an associated value
pub enum FragmentationInformation {
    /// There is no fragmentation
    NoFragmentation,
    /// The packet is an IPv4 packet that couldn't be reassembled yet. The
    /// variant contains the offset and if there are more packets to come
    FragmentedIpv4Packet {
        fragmentation_offset: etherparse::IpFragOffset,
        more_packets: bool,
    },
}

/// An identifier for a comunication between two hosts
pub enum FlowIdentifier {
    TransportFlowIdentifier(TransportFlowIdentifier),
    NetworkFlowIdentifier(NetworkFlowIdentifier),
}

/// An identifier for a comunication between two hosts in the transport layer
#[derive(Debug, Clone, Copy)]
pub struct TransportFlowIdentifier {
    pub(crate) source_ip: IpAddr,
    pub(crate) source_port: u16,
    pub(crate) dest_ip: IpAddr,
    pub(crate) dest_port: u16,
    pub(crate) transport_protocol: IpNumber,
}

/// An identifier for a comunication between two hosts in the network layer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkFlowIdentifier {
    pub(crate) source_ip: IpAddr,
    pub(crate) dest_ip: IpAddr,
    pub(crate) identifier: u32,
}

/// Converts the timestamp of the of the packet to a Datetime<Utc> if its valid
pub fn get_datetime_of_packet(packet_header: &PacketHeader) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(
        packet_header.ts.tv_sec,
        (packet_header.ts.tv_usec * 1_000).try_into().ok()?,
    )
}

/// Try to parse the given packet in the given link type.
pub fn try_parse_packet<'a>(
    link_type: Linktype,
    packet: &'a Packet<'_>,
) -> Result<etherparse::SlicedPacket<'a>, ParseError> {
    match link_type {
        Linktype::ETHERNET => match etherparse::SlicedPacket::from_ethernet(packet.data) {
            Ok(value) => Ok(value),
            Err(err) => Err(ParseError::ErrorOnSlicingPacket(err)),
        },
        Linktype::LINUX_SLL => match etherparse::SlicedPacket::from_linux_sll(packet.data) {
            Ok(value) => Ok(value),
            Err(err) => Err(ParseError::ErrorOnSlicingPacket(err)),
        },
        _ => Err(ParseError::UnsupportedLinkType),
    }
}

impl FlowIdentifier {
    /// Try to extract the relevant flow identifiers from the sliced packet
    pub(crate) fn from_sliced_packet(
        packet: &etherparse::SlicedPacket,
    ) -> Result<(FlowIdentifier, FragmentationInformation), ParseError> {
        let source_ip: IpAddr;
        let dest_ip: IpAddr;
        let transport_protocol: IpNumber;

        match &packet.net {
            Some(header) => match header {
                etherparse::NetSlice::Ipv4(v) => {
                    source_ip = IpAddr::V4(v.header().source_addr());
                    dest_ip = IpAddr::V4(v.header().destination_addr());
                    transport_protocol = v.header().protocol();

                    if v.header().is_fragmenting_payload() {
                        return Ok((
                            FlowIdentifier::NetworkFlowIdentifier(NetworkFlowIdentifier {
                                source_ip,
                                dest_ip,
                                identifier: v.header().identification().into(),
                            }),
                            FragmentationInformation::FragmentedIpv4Packet {
                                fragmentation_offset: v.header().fragments_offset(),
                                more_packets: v.header().more_fragments(),
                            },
                        ));
                    }
                }
                etherparse::NetSlice::Ipv6(v) => {
                    source_ip = IpAddr::V6(v.header().source_addr());
                    dest_ip = IpAddr::V6(v.header().destination_addr());
                    transport_protocol = v.header().next_header();
                }
            },
            None => return Err(ParseError::MissingNetworkLayer),
        }

        let source_port: u16;
        let dest_port: u16;

        match &packet.transport {
            Some(header) => match header {
                etherparse::TransportSlice::Tcp(header) => {
                    source_port = header.source_port();
                    dest_port = header.destination_port();
                }
                etherparse::TransportSlice::Udp(header) => {
                    source_port = header.source_port();
                    dest_port = header.destination_port();
                }
                _ => return Err(ParseError::UnsupportedTransportLayer),
            },
            None => return Err(ParseError::MissingTransportLayer),
        }

        Ok((
            FlowIdentifier::TransportFlowIdentifier(TransportFlowIdentifier {
                source_ip,
                source_port,
                dest_ip,
                dest_port,
                transport_protocol,
            }),
            FragmentationInformation::NoFragmentation,
        ))
    }
}

impl TransportFlowIdentifier {
    #[cfg(test)]
    // Create a new flow identifier from the given params
    pub(crate) fn new(
        source_ip: IpAddr,
        source_port: u16,
        dest_ip: IpAddr,
        dest_port: u16,
        transport_protocol: IpNumber,
    ) -> TransportFlowIdentifier {
        TransportFlowIdentifier {
            source_ip,
            source_port,
            dest_ip,
            dest_port,
            transport_protocol,
        }
    }

    pub(crate) fn write_csv_header<T: ?Sized + std::io::Write>(
        writer: &mut BufWriter<T>,
    ) -> Result<(), Error> {
        write!(
            writer,
            "source_ip,source_port,dest_ip,dest_port,transport_protocol,"
        )?;
        Ok(())
    }

    pub(crate) fn write_csv_value<T: ?Sized + std::io::Write>(
        &self,
        writer: &mut BufWriter<T>,
    ) -> Result<(), Error> {
        write!(
            writer,
            "{},{},{},{},{},",
            self.source_ip,
            self.source_port,
            self.dest_ip,
            self.dest_port,
            self.transport_protocol.0
        )?;
        Ok(())
    }
}

impl PartialEq for TransportFlowIdentifier {
    fn eq(&self, other: &Self) -> bool {
        self.transport_protocol == other.transport_protocol
            && ((self.source_ip == other.source_ip
                && self.source_port == other.source_port
                && self.dest_ip == other.dest_ip
                && self.dest_port == other.dest_port)
                || (self.source_ip == other.dest_ip
                    && self.source_port == other.dest_port
                    && self.dest_ip == other.source_ip
                    && self.dest_port == other.source_port))
    }
}

impl Eq for TransportFlowIdentifier {}

impl Hash for TransportFlowIdentifier {
    fn hash<H: Hasher>(&self, state: &mut H) {
        if self.source_ip <= self.dest_ip {
            self.source_ip.hash(state);
            self.dest_ip.hash(state);
        } else {
            self.dest_ip.hash(state);
            self.source_ip.hash(state);
        }

        if self.source_port <= self.dest_port {
            self.source_port.hash(state);
            self.dest_port.hash(state);
        } else {
            self.dest_port.hash(state);
            self.source_port.hash(state);
        }

        self.transport_protocol.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_eq_transport_pair() {
        let request = TransportFlowIdentifier {
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            source_port: 1234,
            dest_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dest_port: 80,
            transport_protocol: IpNumber::TCP,
        };
        let reply = TransportFlowIdentifier {
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            source_port: 80,
            dest_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            dest_port: 1234,
            transport_protocol: IpNumber::TCP,
        };

        assert!(request == request);
        assert!(request == reply);
        assert!(reply == reply);
        assert!(request == request);
    }
    #[test]
    fn test_different_transport_pairs() {
        let id1 = TransportFlowIdentifier {
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            source_port: 1234,
            dest_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dest_port: 80,
            transport_protocol: IpNumber::TCP,
        };
        let id2 = TransportFlowIdentifier {
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            source_port: 1234,
            dest_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dest_port: 80,
            transport_protocol: IpNumber::UDP,
        };
        let id3 = TransportFlowIdentifier {
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            source_port: 1234,
            dest_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dest_port: 433,
            transport_protocol: IpNumber::TCP,
        };

        assert!(id1 != id2);
        assert!(id1 != id3);
        assert!(id2 != id1);
        assert!(id2 != id3);
        assert!(id3 != id1);
        assert!(id3 != id1);
    }
}
