use super::{FlowStat, FlowTimes};
use crate::{packet_flow::FragmentReasemblyInformation, packet_parse::TransportFlowIdentifier};
use std::io::{BufWriter, Error, Write};

#[derive(Debug)]
pub struct Protocols {
    has_tcp: bool,
    has_udp: bool,
}

struct PacketEval {
    has_tcp: bool,
    has_udp: bool,
}

fn evaluate(sliced_packet: &etherparse::SlicedPacket) -> PacketEval {
    let has_tcp;
    let has_udp;
    match &sliced_packet.transport {
        Some(transport) => match transport {
            etherparse::TransportSlice::Udp(_) => {
                has_tcp = false;
                has_udp = true;
            }
            etherparse::TransportSlice::Tcp(_) => {
                has_tcp = true;
                has_udp = false;
            }
            _ => {
                has_tcp = false;
                has_udp = false;
            }
        },
        None => {
            has_tcp = false;
            has_udp = false;
        }
    }

    PacketEval { has_tcp, has_udp }
}

impl FlowStat for Protocols {
    fn from_packet(
        _identifier: &TransportFlowIdentifier,
        _flow_times: &FlowTimes,
        _packet_header: &pcap::PacketHeader,
        sliced_packet: &etherparse::SlicedPacket,
        _reasembly_information: Option<&FragmentReasemblyInformation>,
    ) -> Self {
        let eval = evaluate(sliced_packet);

        Protocols {
            has_tcp: eval.has_tcp,
            has_udp: eval.has_udp,
        }
    }
    fn include(
        &mut self,
        _identifier: &TransportFlowIdentifier,
        _flow_times: &FlowTimes,
        _packet_header: &pcap::PacketHeader,
        sliced_packet: &etherparse::SlicedPacket,
        _reasembly_information: Option<&FragmentReasemblyInformation>,
    ) {
        let eval = evaluate(sliced_packet);

        self.has_tcp = self.has_tcp || eval.has_tcp;
        self.has_udp = self.has_udp || eval.has_udp;
    }
    fn write_csv_header<T: ?Sized + std::io::Write>(
        writer: &mut BufWriter<T>,
    ) -> Result<(), Error> {
        write!(writer, "has_tcp,")?;
        write!(writer, "has_udp,")?;
        Ok(())
    }
    fn write_csv_value<T: ?Sized + std::io::Write>(
        &self,
        writer: &mut BufWriter<T>,
        _flow_times: &FlowTimes,
    ) -> Result<(), Error> {
        write!(writer, "{},", if self.has_tcp { 1 } else { 0 })?;
        write!(writer, "{},", if self.has_udp { 1 } else { 0 })?;
        Ok(())
    }
}
