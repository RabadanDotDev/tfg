use std::io::{BufWriter, Error, Write};

use chrono::{DateTime, Utc};

use crate::{packet_flow::FragmentReasemblyInformation, packet_parse::{get_datetime_of_packet, TransportFlowIdentifier}};

#[derive(Debug)]
pub struct FlowTimes {
    pub(crate) first_packet_time: DateTime<Utc>,
    pub(crate) last_packet_time: DateTime<Utc>,
}

impl FlowTimes {
    pub fn from_packet(
        _identifier: &TransportFlowIdentifier,
        packet_header: &pcap::PacketHeader,
        _sliced_packet: &etherparse::SlicedPacket,
        reasembly_information: Option<&FragmentReasemblyInformation>,
    ) -> Self {
        let pcap_packet_time = get_datetime_of_packet(packet_header)
            .expect("Packet headers with invalid timestamps are not supported");

        let (first_packet_time, last_packet_time) = match reasembly_information {
            Some(reasembly_information) => (
                std::cmp::min(reasembly_information.first_time, pcap_packet_time),
                std::cmp::max(reasembly_information.last_time, pcap_packet_time),
            ),
            None => (pcap_packet_time, pcap_packet_time),
        };

        FlowTimes {
            first_packet_time,
            last_packet_time,
        }
    }
    pub fn include(
        &mut self,
        _identifier: &TransportFlowIdentifier,
        packet_header: &pcap::PacketHeader,
        _sliced_packet: &etherparse::SlicedPacket,
        reasembly_information: Option<&FragmentReasemblyInformation>,
    ) {
        let pcap_packet_time = get_datetime_of_packet(packet_header)
            .expect("Packet headers with invalid timestamps are not supported");
        let next_time = match reasembly_information {
            Some(reasembly_information) => {
                std::cmp::max(reasembly_information.last_time, pcap_packet_time)
            }
            None => pcap_packet_time,
        };

        self.last_packet_time = next_time
    }
    pub fn write_csv_header<T: ?Sized + std::io::Write>(
        writer: &mut BufWriter<T>,
    ) -> Result<(), Error> {
        write!(writer, "first_packet_time,")?;
        write!(writer, "last_packet_time,")?;
        write!(writer, "duration,")?;
        Ok(())
    }
    pub fn write_csv_value<T: ?Sized + std::io::Write>(
        &self,
        writer: &mut BufWriter<T>,
    ) -> Result<(), Error> {
        write!(writer, "{},", self.first_packet_time.timestamp_micros())?;
        write!(writer, "{},", self.last_packet_time.timestamp_micros())?;
        let duration = (self.last_packet_time - self.first_packet_time)
            .num_microseconds()
            .ok_or(Error::new(std::io::ErrorKind::Other, "Overflow"))?;
        write!(writer, "{},", duration)?;
        Ok(())
    }
    pub fn duration_seconds(&self) -> i64 {
        (self.last_packet_time - self.first_packet_time)
        .num_seconds()
    }
}
