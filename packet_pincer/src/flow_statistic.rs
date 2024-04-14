use std::io::{BufWriter, Error, Write};

use etherparse::SlicedPacket;

pub trait FlowStat {
    fn include<'a>(
        &mut self,
        packet_header: &pcap::PacketHeader,
        sliced_packet: &SlicedPacket<'a>,
    ) -> ();
    fn write_csv_header<T: ?Sized + std::io::Write>(writer: &mut BufWriter<T>) -> Result<(), Error>;
    fn write_csv_value<T: ?Sized + std::io::Write>(&self, writer: &mut BufWriter<T>) -> Result<(), Error>;
}

#[derive(Debug)]
pub struct FlowStatistics {
    packet_count: PacketCount,
    byte_count: ByteCount,
}

impl FlowStatistics {
    pub(crate) fn new() -> FlowStatistics {
        FlowStatistics {
            packet_count: PacketCount::new(),
            byte_count: ByteCount::new()
        }
    }
}

// TODO: create a macro to autogenerate this.
impl FlowStat for FlowStatistics {
    fn include<'a>(
        &mut self,
        packet_header: &pcap::PacketHeader,
        sliced_packet: &SlicedPacket<'a>,
    ) -> () {
        self.packet_count.include(packet_header, sliced_packet);
        self.byte_count.include(packet_header, sliced_packet);
    }
    fn write_csv_header<T: ?Sized + std::io::Write>(writer: &mut BufWriter<T>) -> Result<(), Error> {
        PacketCount::write_csv_header(writer)?;
        write!(writer, ",")?;
        ByteCount::write_csv_header(writer)?;
        Ok(())
    }
    fn write_csv_value<T: ?Sized + std::io::Write>(&self, writer: &mut BufWriter<T>) -> Result<(), Error> {
        self.packet_count.write_csv_value(writer)?;
        write!(writer, ",")?;
        self.byte_count.write_csv_value(writer)?;
        Ok(())
    }
}

#[derive(Debug)]
struct PacketCount {
    count: u64,
}

impl PacketCount {
    fn new() -> PacketCount {
        PacketCount { count: 0 }
    }
}

impl FlowStat for PacketCount {
    fn include<'a>(
        &mut self,
        _packet_header: &pcap::PacketHeader,
        _sliced_packet: &SlicedPacket<'a>,
    ) -> () {
        self.count = self.count + 1;
    }
    fn write_csv_header<T: ?Sized + std::io::Write>(writer: &mut BufWriter<T>) -> Result<(), Error> {
        write!(writer, "packet_count")?;
        Ok(())
    }
    fn write_csv_value<T: ?Sized + std::io::Write>(&self, writer: &mut BufWriter<T>) -> Result<(), Error> {
        write!(writer, "{}", self.count)?;
        Ok(())
    }
}

#[derive(Debug)]
struct ByteCount {
    count: u64,
}

impl ByteCount {
    fn new() -> ByteCount {
        ByteCount { count: 0 }
    }
}

impl FlowStat for ByteCount {
    fn include<'a>(
        &mut self,
        packet_header: &pcap::PacketHeader,
        _sliced_packet: &SlicedPacket<'a>,
    ) -> () {
        self.count = self.count + u64::from(packet_header.len);
    }
    fn write_csv_header<T: ?Sized + std::io::Write>(writer: &mut BufWriter<T>) -> Result<(), Error> {
        write!(writer, "byte_count")?;
        Ok(())
    }
    fn write_csv_value<T: ?Sized + std::io::Write>(&self, writer: &mut BufWriter<T>) -> Result<(), Error> {
        write!(writer, "{}", self.count)?;
        Ok(())
    }
}
