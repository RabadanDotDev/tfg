use etherparse::SlicedPacket;

pub trait Include {
    fn new() -> Self;
    fn include<'a>(
        &mut self,
        packet_header: &pcap::PacketHeader,
        sliced_packet: &SlicedPacket<'a>,
    ) -> ();
}

#[derive(Debug)]
pub struct FlowStatistic {
    packet_count: PacketCount,
    byte_count: ByteCount,
}

// TODO: create a macro to autogenerate this.
impl Include for FlowStatistic {
    fn new() -> FlowStatistic {
        FlowStatistic {
            packet_count: PacketCount::new(),
            byte_count: ByteCount::new()
        }
    }
    fn include<'a>(
        &mut self,
        packet_header: &pcap::PacketHeader,
        sliced_packet: &SlicedPacket<'a>,
    ) -> () {
        self.packet_count.include(packet_header, sliced_packet);
        self.byte_count.include(packet_header, sliced_packet);
    }
}

#[derive(Debug)]
struct PacketCount {
    count: u64,
}

impl Include for PacketCount {
    fn new() -> PacketCount {
        PacketCount { count: 0 }
    }
    fn include<'a>(
        &mut self,
        _packet_header: &pcap::PacketHeader,
        _sliced_packet: &SlicedPacket<'a>,
    ) -> () {
        self.count = self.count + 1;
    }
}

#[derive(Debug)]
struct ByteCount {
    count: u64,
}

impl Include for ByteCount {
    fn new() -> ByteCount {
        ByteCount { count: 0 }
    }
    fn include<'a>(
        &mut self,
        packet_header: &pcap::PacketHeader,
        _sliced_packet: &SlicedPacket<'a>,
    ) -> () {
        self.count = self.count + u64::from(packet_header.len);
    }
}
