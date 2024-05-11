use chrono::{DateTime, TimeDelta, Utc};

use super::{
    extract_byte_count, extract_packet_count, running_stat::RunningStat,
    FlowStat, FlowTimes,
};
use crate::{packet_flow::FragmentReasemblyInformation, packet_parse::TransportFlowIdentifier};
use std::{
    io::{BufWriter, Error, Write},
    net::IpAddr,
};

#[derive(Debug)]
pub struct Activity {
    idle_microseconds: RunningStat,
    active_microseconds: RunningStat,

    last_active_start: DateTime<Utc>,
    last_active_end: DateTime<Utc>,

    active_group_count: u32,

    forward_packet_bytes_sum: u64,
    backward_packet_bytes_sum: u64,
    forward_packet_count: u32,
    backward_packet_count: u32,
}

impl Activity {
    const MAX_DELAY_THESHOLD: TimeDelta = TimeDelta::seconds(1);
}

impl FlowStat for Activity {
    fn from_packet(
        _identifier: &TransportFlowIdentifier,
        flow_times: &FlowTimes,
        packet_header: &pcap::PacketHeader,
        _sliced_packet: &etherparse::SlicedPacket,
        reasembly_information: Option<&FragmentReasemblyInformation>,
    ) -> Self {
        Self {
            idle_microseconds: RunningStat::new(),
            active_microseconds: RunningStat::new(),
            last_active_start: flow_times.first_packet_time,
            last_active_end: flow_times.last_packet_time,
            active_group_count: 1,
            forward_packet_bytes_sum: extract_byte_count(packet_header, reasembly_information),
            backward_packet_bytes_sum: 0,
            forward_packet_count: extract_packet_count(reasembly_information),
            backward_packet_count: 0,
        }
    }
    fn include(
        &mut self,
        identifier: &TransportFlowIdentifier,
        flow_times: &FlowTimes,
        packet_header: &pcap::PacketHeader,
        sliced_packet: &etherparse::SlicedPacket,
        reasembly_information: Option<&FragmentReasemblyInformation>,
    ) {
        // Extract parts
        let byte_count = extract_byte_count(packet_header, reasembly_information);
        let packet_count = extract_packet_count(reasembly_information);
        let is_forward = match &sliced_packet.net {
            Some(header) => match header {
                etherparse::NetSlice::Ipv4(v) => {
                    IpAddr::V4(v.header().source_addr()) == identifier.source_ip
                }
                etherparse::NetSlice::Ipv6(v) => {
                    IpAddr::V6(v.header().source_addr()) == identifier.source_ip
                }
            },
            None => panic!("Unexpected sliced packet without net layer"),
        };
        let last_active_duration = self.last_active_end - self.last_active_start;
        let time_since_last_active = flow_times.last_packet_time - self.last_active_end;

        // Update timing
        if time_since_last_active < Self::MAX_DELAY_THESHOLD {
            self.last_active_end = flow_times.last_packet_time
        } else {
            // Update stats
            self.idle_microseconds.include(
                time_since_last_active
                    .num_microseconds()
                    .unwrap()
                    .try_into()
                    .unwrap(),
            );
            self.active_microseconds.include(
                last_active_duration
                    .num_microseconds()
                    .unwrap()
                    .try_into()
                    .unwrap(),
            );

            // Initialize new active group
            self.active_group_count += 1;
            self.last_active_start = flow_times.last_packet_time;
            self.last_active_end = flow_times.last_packet_time;
        }

        // Count packets
        if is_forward {
            self.forward_packet_bytes_sum += byte_count;
            self.forward_packet_count += packet_count;
        } else {
            self.backward_packet_bytes_sum += byte_count;
            self.backward_packet_count += packet_count;
        }
    }
    fn write_csv_header<T: ?Sized + std::io::Write>(
        writer: &mut BufWriter<T>,
    ) -> Result<(), Error> {
        write!(writer, "idle_seconds_min,")?;
        write!(writer, "idle_seconds_max,")?;
        write!(writer, "idle_seconds_mean,")?;
        write!(writer, "idle_seconds_std,")?;

        write!(writer, "active_seconds_min,")?;
        write!(writer, "active_seconds_max,")?;
        write!(writer, "active_seconds_mean,")?;
        write!(writer, "active_seconds_std,")?;

        write!(writer, "active_group_forward_packet_average,")?;
        write!(writer, "active_group_backward_packet_average,")?;

        write!(writer, "active_group_forward_byte_average,")?;
        write!(writer, "active_group_backward_byte_average,")?;

        write!(writer, "active_group_forward_byte_second_average,")?;
        write!(writer, "active_group_backward_byte_second_average,")?;

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
            (self.idle_microseconds.current_max().unwrap_or(0) as f64) / 1_000_000.0
        )?;
        write!(
            writer,
            "{:.9},",
            (self.idle_microseconds.current_min().unwrap_or(0) as f64) / 1_000_000.0
        )?;
        write!(
            writer,
            "{:.9},",
            self.idle_microseconds.current_mean() / 1_000_000.0
        )?;
        write!(
            writer,
            "{:.9},",
            self.idle_microseconds.current_standard_deviation() / 1_000_000.0
        )?;

        write!(
            writer,
            "{:.9},",
            (self.active_microseconds.current_max().unwrap_or(0) as f64) / 1_000_000.0
        )?;
        write!(
            writer,
            "{:.9},",
            (self.active_microseconds.current_min().unwrap_or(0) as f64) / 1_000_000.0
        )?;
        write!(
            writer,
            "{:.9},",
            self.active_microseconds.current_mean() / 1_000_000.0
        )?;
        write!(
            writer,
            "{:.9},",
            self.active_microseconds.current_standard_deviation() / 1_000_000.0
        )?;

        write!(
            writer,
            "{:.9},",
            self.forward_packet_count as f64 / self.active_group_count as f64
        )?;
        write!(
            writer,
            "{:.9},",
            self.backward_packet_count as f64 / self.active_group_count as f64
        )?;

        write!(
            writer,
            "{:.9},",
            self.forward_packet_bytes_sum as f64 / self.active_group_count as f64
        )?;
        write!(
            writer,
            "{:.9},",
            self.backward_packet_bytes_sum as f64 / self.active_group_count as f64
        )?;

        let active_time = self.active_microseconds.current_sum();

        if active_time == 0 {
            write!(writer, "{},", 0)?;
            write!(writer, "{},", 0)?;
        } else {
            let active_time = active_time as f64 / 1_000_000.0;

            write!(
                writer,
                "{:.9},",
                self.forward_packet_bytes_sum as f64 / active_time / self.active_group_count as f64
            )?;
            write!(
                writer,
                "{:.9},",
                self.backward_packet_bytes_sum as f64
                    / active_time
                    / self.active_group_count as f64
            )?;
        }

        Ok(())
    }
}
