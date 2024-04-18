use chrono::DateTime;
use chrono::Utc;
use etherparse::err::packet::SliceError;
use etherparse::IpNumber;
use etherparse::SlicedPacket;
use std::hash::{Hash, Hasher};
use std::io::{BufWriter, Error, Write};
use std::net::IpAddr;

use pcap::PacketHeader;
use pcap::{Linktype, Packet};

#[derive(Debug)]
pub enum ParseError {
    UnsupportedLinkType,
    ErrorOnSlicingPacket(SliceError),
    MissingNetworkLayer,
    MissingTransportLayer,
    UnsupportedTransportLayer,
}

pub struct FragmentationInformation(());

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
) -> Result<SlicedPacket<'a>, ParseError> {
    match link_type {
        Linktype::ETHERNET => match SlicedPacket::from_ethernet(packet.data) {
            Ok(value) => Ok(value),
            Err(err) => Err(ParseError::ErrorOnSlicingPacket(err)),
        },
        Linktype::LINUX_SLL => Err(ParseError::UnsupportedLinkType), // TODO: implement sll suport
        _ => Err(ParseError::UnsupportedLinkType),
    }
}

/// An identifier for a comunication between two hosts
#[derive(Debug, Clone, Copy)]
pub struct FlowIdentifier {
    pub(crate) source_ip: IpAddr,
    pub(crate) source_port: u16,
    pub(crate) dest_ip: IpAddr,
    pub(crate) dest_port: u16,
    pub(crate) transport_protocol: IpNumber,
}

impl FlowIdentifier {
    #[cfg(test)]
    // Create a new flow identifier from the given params
    pub(crate) fn new(
        source_ip: IpAddr,
        source_port: u16,
        dest_ip: IpAddr,
        dest_port: u16,
        transport_protocol: IpNumber,
    ) -> FlowIdentifier {
        FlowIdentifier {
            source_ip,
            source_port,
            dest_ip,
            dest_port,
            transport_protocol,
        }
    }

    /// Try to extract the relevant flow identifiers from the sliced packet
    pub(crate) fn from_sliced_packet(
        packet: &SlicedPacket,
    ) -> Result<(FlowIdentifier, FragmentationInformation), ParseError> {
        let source_ip: IpAddr;
        let source_port: u16;
        let dest_ip: IpAddr;
        let dest_port: u16;
        let transport_protocol: IpNumber;

        match &packet.net {
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
            None => return Err(ParseError::MissingNetworkLayer),
        }

        // TODO check if its fragmented, try reassembling the packet or storing
        // the fragment it should discard older fragments after some iterations
        // there are double fragmentations, where there the same packet
        // fragments are sent twice, it should be ignored, held or another
        // action? or maybe just keep them until they get eventually discarded.
        // if there are detected repeated fragments, before the reassembly,
        // they should be counted

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
            FlowIdentifier {
                source_ip,
                source_port,
                dest_ip,
                dest_port,
                transport_protocol,
            },
            FragmentationInformation(()),
        ))
    }

    pub(crate) fn write_csv_header<T: ?Sized + std::io::Write>(
        writer: &mut BufWriter<T>,
    ) -> Result<(), Error> {
        write!(
            writer,
            "source_ip,source_port,dest_ip,dest_port,is_tcp,is_udp"
        )?;
        Ok(())
    }

    pub(crate) fn write_csv_value<T: ?Sized + std::io::Write>(
        &self,
        writer: &mut BufWriter<T>,
    ) -> Result<(), Error> {
        write!(
            writer,
            "{},{},{},{},",
            self.source_ip, self.source_port, self.dest_ip, self.dest_port
        )?;
        match self.transport_protocol {
            IpNumber::TCP => write!(writer, "{},{}", 1, 0)?,
            IpNumber::UDP => write!(writer, "{},{}", 0, 1)?,
            _ => write!(writer, "{},{}", 0, 0)?,
        }
        Ok(())
    }
}

impl PartialEq for FlowIdentifier {
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

impl Eq for FlowIdentifier {}

impl Hash for FlowIdentifier {
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
        let request = FlowIdentifier {
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            source_port: 1234,
            dest_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dest_port: 80,
            transport_protocol: IpNumber::TCP,
        };
        let reply = FlowIdentifier {
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
        let id1 = FlowIdentifier {
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            source_port: 1234,
            dest_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dest_port: 80,
            transport_protocol: IpNumber::TCP,
        };
        let id2 = FlowIdentifier {
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            source_port: 1234,
            dest_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dest_port: 80,
            transport_protocol: IpNumber::UDP,
        };
        let id3 = FlowIdentifier {
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
