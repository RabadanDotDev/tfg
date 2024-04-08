use std::path::{Path, PathBuf};
use chrono::{DateTime, Utc};
use walkdir::WalkDir;
use pcap::{Capture, PacketHeader};

fn get_datetime_of_packet(packet_header: &PacketHeader) -> DateTime<Utc> {
  DateTime::from_timestamp(
    packet_header.ts.tv_sec, 
    (packet_header.ts.tv_usec*1_000).try_into().expect("Packet headers with invalid timestamps are not supported")
  ).expect("Packet headers with invalid timestamps are not supported")
}

#[derive(Debug)]
#[non_exhaustive]
pub struct PcapList {
  paths: Vec<PathBuf>
}

impl PcapList {
  pub fn from(directory: &Path) -> PcapList {
    // Get list of avalable pcaps and first timestamps
    let mut paths: Vec<_> = WalkDir::new(directory).into_iter()
      .filter_map(|position| position.ok()) // filter valid dir entries
      .map(|dir_entry| dir_entry.into_path()) // extract paths from dir entries
      .filter_map(|path| Capture::from_file(&path).ok().and_then(|capture| Some((path, capture)))) // open pcaps while conserving path
      .filter_map(|(path, mut capture)| capture.next_packet().ok().and_then(|packet| Some((path, packet.header.to_owned())))) // get first packets
      .map(|(path, packet_header)| (path, get_datetime_of_packet(&packet_header))) // get timestamps
      .collect(); // convert to vector

    // Sort the list
    paths.sort();

    // Discard timestamps
    let paths = paths.into_iter().map(|(path, _packet)| path).collect();

    // Construct 
    PcapList {
      paths
    }
  }
}
