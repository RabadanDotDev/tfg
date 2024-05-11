use std::io::{BufWriter, Error, Write};

use chrono::{DateTime, TimeDelta, Utc};

use crate::{
    packet_flow::FragmentReasemblyInformation,
    packet_parse::{get_datetime_of_packet, TransportFlowIdentifier},
};

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
        write!(writer, "duration_seconds,")?;
        Ok(())
    }
    pub fn write_csv_value<T: ?Sized + std::io::Write>(
        &self,
        writer: &mut BufWriter<T>,
    ) -> Result<(), Error> {
        let duration = self.last_packet_time - self.first_packet_time;
        write!(writer, "{},", self.first_packet_time.timestamp_micros())?;
        write!(writer, "{},", self.last_packet_time.timestamp_micros())?;
        write!(
            writer,
            "{}.{:09},",
            duration.num_seconds(),
            duration.subsec_nanos()
        )?;
        Ok(())
    }
    pub fn duration(&self) -> TimeDelta {
        self.last_packet_time - self.first_packet_time
    }
    pub fn duration_seconds_f64(&self) -> f64 {
        let duration = self.duration();
        duration.subsec_nanos() as f64 + (duration.num_seconds() as f64) * 1_000_000_000.0
    }
}
