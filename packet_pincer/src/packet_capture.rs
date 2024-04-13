use pcap::{Active, Capture, Linktype, Offline, Packet};
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
    FileCapture(FileCaptureList),
    /// Packet capture coming from a device
    DeviceCapture(Capture<Active>),
}

impl PacketCapture {
    /// Create a `PacketCapture`` from the valid files under a given directory
    pub fn from_directory(directory: &Path) -> PacketCapture {
        return Self::FileCapture(FileCaptureList::from(directory));
    }

    /// Create a `PacketCapture from a capture device
    pub fn from_device(device: pcap::Device) -> Result<PacketCapture, pcap::Error> {
        let capture = Capture::from_device(device)?.timeout(1000).open()?;
        Ok(Self::DeviceCapture(capture))
    }

    /// Try process next packet if possible. Blocks until a packet is received
    /// in the case of device captures.
    pub fn try_process_next<F>(&mut self, process_packet: &mut F) -> bool
    where
        F: FnMut(PacketOrigin, Linktype, &Packet<'_>) -> (),
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
                        println!("Error on extracting next packet from device: {}", err);
                        false
                    }
                }
            }
        }
    }
}

struct FileCapture {
    capture_path: PathBuf,
    capture: Capture<Offline>,
}

/// A list of offline captures sorted by the first available timestamp
#[non_exhaustive]
pub struct FileCaptureList {
    current_capture: Option<FileCapture>,
    captures_iterator: Box<dyn Iterator<Item = FileCapture>>,
}

impl FileCaptureList {
    /// Create a `OfflineCaptureList` with all the valid captures under the
    /// given Path.
    fn from(directory: &Path) -> FileCaptureList {
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
                Some(FileCapture {
                    capture_path,
                    capture,
                })
            })
        });

        // Construct
        FileCaptureList {
            current_capture: None,
            captures_iterator: Box::new(captures_iterator),
        }
    }

    /// Process next packet with the given clousure if it exists.
    fn try_process_next<F>(&mut self, process_packet: &mut F) -> bool
    where
        F: FnMut(PacketOrigin, Linktype, &Packet<'_>) -> (),
    {
        loop {
            match self.current_capture {
                None => match self.captures_iterator.next() {
                    None => return false,
                    Some(next_capture) => {
                        println!(
                            "Current capture path changed to {}",
                            next_capture.capture_path.display()
                        );
                        self.current_capture = Some(next_capture);
                    }
                },
                Some(ref mut current_capture) => {
                    let datalink = current_capture.capture.get_datalink();
                    match current_capture.capture.next_packet() {
                        Err(err) => {
                            println!(
                                "Could not extract next packet of current capture from path {}: {}",
                                current_capture.capture_path.display(),
                                err
                            );
                            self.current_capture = None;
                        }
                        Ok(packet) => {
                            process_packet(
                                PacketOrigin::File(current_capture.capture_path.as_path()),
                                datalink,
                                &packet,
                            );
                            return true;
                        }
                    }
                }
            }
        }
    }
}
