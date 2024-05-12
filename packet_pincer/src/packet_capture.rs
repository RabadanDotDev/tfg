use chrono::{DateTime, Utc};
use log::{error, info};
use pcap::{Active, Capture, Linktype, Offline, Packet};
use priority_queue::PriorityQueue;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::packet_parse::get_datetime_of_packet;

/// Packet origin
pub enum PacketOrigin<'a> {
    /// The origin of the packet is a capture file
    File(&'a Path),
    /// The origin of the packet is a real network device
    Device(),
}

/// Packet capture origin
pub enum PacketCapture {
    /// Packet capture coming from a list of capture files
    FileCapture(FileCaptureCollection),
    /// Packet capture coming from a device
    DeviceCapture(Capture<Active>),
}

impl PacketCapture {
    /// Create a `PacketCapture`` from the valid files under a given directory
    pub fn from_directory(directory: &Path) -> PacketCapture {
        Self::FileCapture(FileCaptureCollection::from(directory.to_owned()))
    }

    /// Create a `PacketCapture from a capture device
    pub fn from_device(device: pcap::Device) -> Result<PacketCapture, pcap::Error> {
        let capture = Capture::from_device(device)?.timeout(1000).open()?;
        Ok(Self::DeviceCapture(capture))
    }

    /// Try process next packet if possible. Blocks until a packet is read
    pub fn try_process_next<F>(&mut self, process_packet: &mut F) -> bool
    where
        F: FnMut(PacketOrigin, Linktype, &Packet<'_>),
    {
        match self {
            Self::FileCapture(file_capture_list) => {
                file_capture_list.try_process_next(process_packet)
            }
            Self::DeviceCapture(capture) => {
                let datalink = capture.get_datalink();
                match capture.next_packet() {
                    Ok(packet) => {
                        process_packet(PacketOrigin::Device(), datalink, &packet);
                        true
                    }
                    Err(err) => {
                        error!("Error on extracting next packet from device: {}", err);
                        false
                    }
                }
            }
        }
    }
}

struct FileCapture {
    capture_path: PathBuf,
    next_extracted_packet: OwnedPacket,
    capture: Capture<Offline>,
}

impl PartialEq for FileCapture {
    fn eq(&self, other: &Self) -> bool {
        self.capture_path == other.capture_path
    }
}

impl Eq for FileCapture {}

impl Hash for FileCapture {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.capture_path.hash(state);
    }
}

/// A list of offline captures sorted by the first available timestamp
#[non_exhaustive]
pub struct FileCaptureCollection {
    captures_map: HashMap<PathBuf, FileCapture>,
    captures_queue: PriorityQueue<PathBuf, std::cmp::Reverse<DateTime<Utc>>>,
}

#[derive(Debug)]
struct OwnedPacket {
    header: pcap::PacketHeader,
    data: Vec<u8>,
}

impl OwnedPacket {
    fn from(packet: &pcap::Packet) -> OwnedPacket {
        OwnedPacket {
            header: packet.header.clone(),
            data: packet.data.to_owned(),
        }
    }

    fn as_ref<'a>(&'a self) -> pcap::Packet<'a> {
        pcap::Packet {
            header: &self.header,
            data: &self.data,
        }
    }
}

impl FileCaptureCollection {
    /// Create a `OfflineCaptureList` with all the valid captures under the
    /// given Path.
    fn from(directory: PathBuf) -> FileCaptureCollection {
        let mut captures_queue: PriorityQueue<PathBuf, std::cmp::Reverse<DateTime<Utc>>> = PriorityQueue::new();
        let mut captures_map: HashMap<PathBuf, FileCapture> = HashMap::new();

        // Get list of file captures
        WalkDir::new(directory)
            .into_iter()
            .filter_map(|position| position.ok())
            .map(|dir_entry| dir_entry.into_path())
            .filter_map(|path| {
                Capture::from_file(&path)
                    .ok()
                    .map(|capture| (path, capture))
            })
            .filter_map(|(capture_path, mut capture)| {
                let next_extracted_packet = OwnedPacket::from(&capture.next_packet().ok()?);
                Some(FileCapture {
                    capture_path,
                    capture,
                    next_extracted_packet,
                })
            }).for_each(|capture| {
                let time = get_datetime_of_packet(&capture.next_extracted_packet.header)
                    .expect("Packet headers with invalid timestamps are not supported");
                let path = capture.capture_path.clone();

                captures_queue.push(path.clone(), std::cmp::Reverse(time));
                captures_map.insert(path, capture);
            });

        // Construct
        FileCaptureCollection {
            captures_queue,
            captures_map,
        }
    }

    /// Process next packet with the given clousure if it exists.
    fn try_process_next<F>(&mut self, process_packet: &mut F) -> bool
    where
        F: FnMut(PacketOrigin, Linktype, &Packet<'_>),
    {
        // Determine the next file capture
        let file_capture_path = match self.captures_queue.peek() {
            None => return false,
            Some((file_capture, _)) => file_capture.clone(),
        };

        // Process packet
        let file_capture = self.captures_map.get_mut(&file_capture_path).expect("Queue and map must be consistent");
        process_packet(
            PacketOrigin::File(file_capture.capture_path.as_path()),
            file_capture.capture.get_datalink(),
            &file_capture.next_extracted_packet.as_ref(),
        );

        // Extract next packet
        let next_extracted_packet = match file_capture.capture.next_packet() {
            Ok(packet) => Ok(OwnedPacket::from(&packet)),
            Err(err) => Err(err),
        };

        // Update priorities
        match next_extracted_packet {
            Ok(packet) => {
                // Update map
                file_capture.next_extracted_packet = packet;

                // Update queue
                let time = get_datetime_of_packet(&file_capture.next_extracted_packet.header)
                    .expect("Packet headers with invalid timestamps are not supported");
                self.captures_queue.change_priority(&file_capture_path, std::cmp::Reverse(time));
            },
            Err(err) => {
                info!("Closing {} because {}. {} files are left", file_capture_path.display(), err, self.captures_queue.len()-1);

                // Update map
                self.captures_map.remove(&file_capture_path);

                // Update queue
                self.captures_queue.remove(&file_capture_path);
            }
        }

        return true;
    }
}
