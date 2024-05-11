use super::{running_stat::RunningStat, FlowStat, FlowTimes};
use crate::{packet_flow::FragmentReasemblyInformation, packet_parse::TransportFlowIdentifier};
use chrono::{DateTime, Utc};
use std::{
    io::{BufWriter, Error, Write},
    net::IpAddr,
};

#[derive(Debug)]
pub struct Interarrival {
    bidirectional_last_time: DateTime<Utc>,
    forward_last_time: DateTime<Utc>,
    backward_last_time: Option<DateTime<Utc>>,
    bidirectional_iat: RunningStat,
    forward_iat: RunningStat,
    backward_iat: RunningStat,
}

impl FlowStat for Interarrival {
    fn from_packet(
        _identifier: &TransportFlowIdentifier,
        flow_times: &FlowTimes,
        _packet_header: &pcap::PacketHeader,
        _sliced_packet: &etherparse::SlicedPacket,
        _reasembly_information: Option<&FragmentReasemblyInformation>,
    ) -> Self {
        let bidirectional_last_time = flow_times.last_packet_time;
        let forward_last_time = flow_times.last_packet_time;
        let backward_last_time = None;
        let bidirectional_iat = RunningStat::new();
        let forward_iat = RunningStat::new();
        let backward_iat = RunningStat::new();

        Interarrival {
            bidirectional_last_time,
            forward_last_time,
            backward_last_time,
            bidirectional_iat,
            forward_iat,
            backward_iat,
        }
    }
    fn include(
        &mut self,
        identifier: &TransportFlowIdentifier,
        flow_times: &FlowTimes,
        _packet_header: &pcap::PacketHeader,
        sliced_packet: &etherparse::SlicedPacket,
        _reasembly_information: Option<&FragmentReasemblyInformation>,
    ) {
        let src_ip = match &sliced_packet.net {
            Some(header) => match header {
                etherparse::NetSlice::Ipv4(v) => IpAddr::V4(v.header().source_addr()),
                etherparse::NetSlice::Ipv6(v) => IpAddr::V6(v.header().source_addr()),
            },
            None => panic!("Unexpected sliced packet without net layer"),
        };
        let time = flow_times.last_packet_time;

        // Update bidirectional
        let bidirectional_increment: u64 = (time - self.bidirectional_last_time)
            .num_microseconds()
            .expect("IAT increments microseconds should fit in a i64")
            .try_into()
            .expect("IAT increments microseconds should convert to u64");

        self.bidirectional_iat.include(bidirectional_increment);
        self.bidirectional_last_time = time;

        // Update direction
        if src_ip == identifier.source_ip {
            let forward_increment: u64 =
                (time - self.forward_last_time).num_microseconds().unwrap() as u64;
            self.forward_iat.include(forward_increment);
            self.forward_last_time = time;
        } else if let Some(backward_last_time) = self.backward_last_time {
            let backward_increment: u64 =
                (time - backward_last_time).num_microseconds().unwrap() as u64;
            self.bidirectional_iat.include(backward_increment);
            self.backward_last_time = Some(time);
        } else {
            self.backward_last_time = Some(time);
        }
    }
    fn write_csv_header<T: ?Sized + std::io::Write>(
        writer: &mut BufWriter<T>,
    ) -> Result<(), Error> {
        write!(writer, "bidirectional_inter_arrival_time_max,")?;
        write!(writer, "bidirectional_inter_arrival_time_min,")?;
        write!(writer, "bidirectional_inter_arrival_time_mean,")?;
        write!(writer, "bidirectional_inter_arrival_time_std,")?;

        write!(writer, "forward_inter_arrival_time_max,")?;
        write!(writer, "forward_inter_arrival_time_min,")?;
        write!(writer, "forward_inter_arrival_time_mean,")?;
        write!(writer, "forward_inter_arrival_time_std,")?;

        write!(writer, "backward_inter_arrival_time_max,")?;
        write!(writer, "backward_inter_arrival_time_min,")?;
        write!(writer, "backward_inter_arrival_time_mean,")?;
        write!(writer, "backward_inter_arrival_time_std,")?;

        Ok(())
    }
    fn write_csv_value<T: ?Sized + std::io::Write>(
        &self,
        writer: &mut BufWriter<T>,
        _flow_times: &FlowTimes,
    ) -> Result<(), Error> {
        write!(
            writer,
            "{:.9},",
            (self.bidirectional_iat.current_max().unwrap_or(0) as f64) / 1_000_000.0
        )?;
        write!(
            writer,
            "{:.9},",
            (self.bidirectional_iat.current_min().unwrap_or(0) as f64) / 1_000_000.0
        )?;
        write!(
            writer,
            "{:.9},",
            self.bidirectional_iat.current_mean() / 1_000_000.0
        )?;
        write!(
            writer,
            "{:.9},",
            self.bidirectional_iat.current_standard_deviation() / 1_000_000.0
        )?;

        write!(
            writer,
            "{:.9},",
            (self.forward_iat.current_max().unwrap_or(0) as f64) / 1_000_000.0
        )?;
        write!(
            writer,
            "{:.9},",
            (self.forward_iat.current_min().unwrap_or(0) as f64) / 1_000_000.0
        )?;
        write!(
            writer,
            "{:.9},",
            self.forward_iat.current_mean() / 1_000_000.0
        )?;
        write!(
            writer,
            "{:.9},",
            self.forward_iat.current_standard_deviation() / 1_000_000.0
        )?;

        write!(
            writer,
            "{:.9},",
            (self.backward_iat.current_max().unwrap_or(0) as f64) / 1_000_000.0
        )?;
        write!(
            writer,
            "{:.9},",
            (self.backward_iat.current_min().unwrap_or(0) as f64) / 1_000_000.0
        )?;
        write!(
            writer,
            "{:.9},",
            self.backward_iat.current_mean() / 1_000_000.0
        )?;
        write!(
            writer,
            "{:.9},",
            self.backward_iat.current_standard_deviation() / 1_000_000.0
        )?;

        Ok(())
    }
}
