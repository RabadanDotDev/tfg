use std::{
    cmp::{max, min},
    io::{BufWriter, Error, Write},
};

use chrono::{DateTime, Utc};

use crate::{packet_flow::FragmentReasemblyInformation, packet_parse::get_datetime_of_packet};

pub trait FlowStat {
    fn from_packet(
        packet_header: &pcap::PacketHeader,
        sliced_packet: &etherparse::SlicedPacket,
        reasembly_information: Option<&FragmentReasemblyInformation>,
    ) -> Self;
    fn include(
        &mut self,
        packet_header: &pcap::PacketHeader,
        sliced_packet: &etherparse::SlicedPacket,
        reasembly_information: Option<&FragmentReasemblyInformation>,
    );
    fn write_csv_header<T: ?Sized + std::io::Write>(writer: &mut BufWriter<T>)
        -> Result<(), Error>;
    fn write_csv_value<T: ?Sized + std::io::Write>(
        &self,
        writer: &mut BufWriter<T>,
    ) -> Result<(), Error>;
}

#[derive(Debug)]
pub struct FlowStatistics {
    pub(crate) flow_times: FlowTimes,
    packet_count: PacketCount,
    byte_count: ByteCount,
}

// TODO: create a macro to autogenerate this.
impl FlowStat for FlowStatistics {
    fn from_packet(
        packet_header: &pcap::PacketHeader,
        sliced_packet: &etherparse::SlicedPacket,
        reasembly_information: Option<&FragmentReasemblyInformation>,
    ) -> Self {
        FlowStatistics {
            flow_times: FlowTimes::from_packet(packet_header, sliced_packet, reasembly_information),
            packet_count: PacketCount::from_packet(
                packet_header,
                sliced_packet,
                reasembly_information,
            ),
            byte_count: ByteCount::from_packet(packet_header, sliced_packet, reasembly_information),
        }
    }
    fn include(
        &mut self,
        packet_header: &pcap::PacketHeader,
        sliced_packet: &etherparse::SlicedPacket,
        reasembly_information: Option<&FragmentReasemblyInformation>,
    ) {
        self.flow_times
            .include(packet_header, sliced_packet, reasembly_information);
        self.packet_count
            .include(packet_header, sliced_packet, reasembly_information);
        self.byte_count
            .include(packet_header, sliced_packet, reasembly_information);
    }
    fn write_csv_header<T: ?Sized + std::io::Write>(
        writer: &mut BufWriter<T>,
    ) -> Result<(), Error> {
        FlowTimes::write_csv_header(writer)?;
        write!(writer, ",")?;
        PacketCount::write_csv_header(writer)?;
        write!(writer, ",")?;
        ByteCount::write_csv_header(writer)?;
        Ok(())
    }
    fn write_csv_value<T: ?Sized + std::io::Write>(
        &self,
        writer: &mut BufWriter<T>,
    ) -> Result<(), Error> {
        self.flow_times.write_csv_value(writer)?;
        write!(writer, ",")?;
        self.packet_count.write_csv_value(writer)?;
        write!(writer, ",")?;
        self.byte_count.write_csv_value(writer)?;
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct FlowTimes {
    pub(crate) first_packet_time: DateTime<Utc>,
    pub(crate) last_packet_time: DateTime<Utc>,
}

impl FlowStat for FlowTimes {
    fn from_packet(
        packet_header: &pcap::PacketHeader,
        _sliced_packet: &etherparse::SlicedPacket,
        reasembly_information: Option<&FragmentReasemblyInformation>,
    ) -> Self {
        let pcap_packet_time = get_datetime_of_packet(packet_header)
            .expect("Packet headers with invalid timestamps are not supported");

        let (first_packet_time, last_packet_time) = match reasembly_information {
            Some(reasembly_information) => (
                min(reasembly_information.first_time, pcap_packet_time),
                max(reasembly_information.last_time, pcap_packet_time),
            ),
            None => (pcap_packet_time, pcap_packet_time),
        };

        FlowTimes {
            first_packet_time,
            last_packet_time,
        }
    }
    fn include(
        &mut self,
        packet_header: &pcap::PacketHeader,
        _sliced_packet: &etherparse::SlicedPacket,
        reasembly_information: Option<&FragmentReasemblyInformation>,
    ) {
        let pcap_packet_time = get_datetime_of_packet(packet_header)
            .expect("Packet headers with invalid timestamps are not supported");

        self.last_packet_time = match reasembly_information {
            Some(reasembly_information) => max(reasembly_information.last_time, pcap_packet_time),
            None => pcap_packet_time,
        };
    }
    fn write_csv_header<T: ?Sized + std::io::Write>(
        writer: &mut BufWriter<T>,
    ) -> Result<(), Error> {
        write!(writer, "first_packet_time")?;
        write!(writer, ",")?;
        write!(writer, "last_packet_time")?;
        write!(writer, ",")?;
        write!(writer, "duration")?;
        Ok(())
    }
    fn write_csv_value<T: ?Sized + std::io::Write>(
        &self,
        writer: &mut BufWriter<T>,
    ) -> Result<(), Error> {
        write!(writer, "{}", self.first_packet_time.timestamp_micros())?;
        write!(writer, ",")?;
        write!(writer, "{}", self.last_packet_time.timestamp_micros())?;
        write!(writer, ",")?;
        let duration = (self.last_packet_time - self.first_packet_time)
            .num_microseconds()
            .ok_or(Error::new(std::io::ErrorKind::Other, "Overflow"))?;
        write!(writer, "{}", duration)?;
        Ok(())
    }
}

#[derive(Debug)]
struct PacketCount {
    count: u64,
}

impl FlowStat for PacketCount {
    fn from_packet(
        _packet_header: &pcap::PacketHeader,
        _sliced_packet: &etherparse::SlicedPacket,
        reasembly_information: Option<&FragmentReasemblyInformation>,
    ) -> Self {
        let count = match reasembly_information {
            Some(reasembly_information) => {
                reasembly_information.total_fragments_received_count.into()
            }
            None => 1,
        };
        PacketCount { count }
    }
    fn include(
        &mut self,
        _packet_header: &pcap::PacketHeader,
        _sliced_packet: &etherparse::SlicedPacket,
        reasembly_information: Option<&FragmentReasemblyInformation>,
    ) {
        let count = match reasembly_information {
            Some(reasembly_information) => reasembly_information.total_bytes_received_count.into(),
            None => 1,
        };

        self.count += count;
    }
    fn write_csv_header<T: ?Sized + std::io::Write>(
        writer: &mut BufWriter<T>,
    ) -> Result<(), Error> {
        write!(writer, "packet_count")?;
        Ok(())
    }
    fn write_csv_value<T: ?Sized + std::io::Write>(
        &self,
        writer: &mut BufWriter<T>,
    ) -> Result<(), Error> {
        write!(writer, "{}", self.count)?;
        Ok(())
    }
}

#[derive(Debug)]
struct ByteCount {
    count: u64,
}

impl FlowStat for ByteCount {
    fn from_packet(
        packet_header: &pcap::PacketHeader,
        _sliced_packet: &etherparse::SlicedPacket,
        reasembly_information: Option<&FragmentReasemblyInformation>,
    ) -> Self {
        let count = match reasembly_information {
            Some(reasembly_information) => reasembly_information.total_bytes_received_count.into(),
            None => packet_header.len.into(),
        };

        ByteCount { count }
    }
    fn include(
        &mut self,
        packet_header: &pcap::PacketHeader,
        _sliced_packet: &etherparse::SlicedPacket,
        reasembly_information: Option<&FragmentReasemblyInformation>,
    ) {
        let count: u64 = match reasembly_information {
            Some(reasembly_information) => reasembly_information.total_bytes_received_count.into(),
            None => packet_header.len.into(),
        };

        self.count += count;
    }
    fn write_csv_header<T: ?Sized + std::io::Write>(
        writer: &mut BufWriter<T>,
    ) -> Result<(), Error> {
        write!(writer, "byte_count")?;
        Ok(())
    }
    fn write_csv_value<T: ?Sized + std::io::Write>(
        &self,
        writer: &mut BufWriter<T>,
    ) -> Result<(), Error> {
        write!(writer, "{}", self.count)?;
        Ok(())
    }
}
