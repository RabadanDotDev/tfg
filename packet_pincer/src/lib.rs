#![deny(missing_docs)]

//! Online and offline network traffic analyzer

use chrono::{DateTime, Utc};
use pcap::{Capture, Offline, Packet, PacketHeader};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

fn get_datetime_of_packet(packet_header: &PacketHeader) -> DateTime<Utc> {
    DateTime::from_timestamp(
        packet_header.ts.tv_sec,
        (packet_header.ts.tv_usec * 1_000)
            .try_into()
            .expect("Packet headers with invalid timestamps are not supported"),
    )
    .expect("Packet headers with invalid timestamps are not supported")
}

struct OpenOfflineCapture {
    capture_path: PathBuf,
    capture: Capture<Offline>,
}

/// A list of offline captures sorted by the first available timestamp
#[non_exhaustive]
pub struct OfflineCaptureList {
    current_capture: Option<OpenOfflineCapture>,
    captures_iterator: Box<dyn Iterator<Item = OpenOfflineCapture>>,
}

impl OfflineCaptureList {
    /// Create a `OfflineCaptureList` with all the valid captures under the
    /// given Path.
    pub fn from(directory: &Path) -> OfflineCaptureList {
        // Get list of avalable pcaps and first timestamps
        let mut paths: Vec<_> = WalkDir::new(directory)
            .into_iter()
            .filter_map(|position| position.ok())
            .map(|dir_entry| dir_entry.into_path())
            .filter_map(|path| {
                Capture::from_file(&path)
                    .ok()
                    .and_then(|capture| Some((path, capture)))
            })
            .filter_map(|(path, mut capture)| {
                capture
                    .next_packet()
                    .ok()
                    .and_then(|packet| Some((path, packet.header.to_owned())))
            })
            .map(|(path, packet_header)| (path, get_datetime_of_packet(&packet_header)))
            .collect();

        // Sort the list
        paths.sort();

        // Open sorted captures
        let captures_iterator = paths.into_iter().filter_map(|(capture_path, _time)| {
            Capture::from_file(&capture_path).ok().and_then(|capture| {
                Some(OpenOfflineCapture {
                    capture_path,
                    capture,
                })
            })
        });

        // Construct
        OfflineCaptureList {
            current_capture: None,
            captures_iterator: Box::new(captures_iterator),
        }
    }

    /// Process next packet with the given clousure if it exists.
    pub fn try_process_next<F>(&mut self, process_packet: &mut F) -> bool
    where
        F: FnMut(&Path, &Packet<'_>) -> (),
    {
        loop {
            match self.current_capture {
                None => match self.captures_iterator.next() {
                    None => return false,
                    Some(next_capture) => self.current_capture = Some(next_capture),
                },
                Some(ref mut current_capture) => match current_capture.capture.next_packet().ok() {
                    None => self.current_capture = None,
                    Some(packet) => {
                        process_packet(&current_capture.capture_path, &packet);
                        return true;
                    }
                },
            }
        }
    }
}
