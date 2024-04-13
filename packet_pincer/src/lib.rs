#![warn(missing_docs)]

//! Online and offline network traffic analyzer

mod packet_capture;
mod packet_parse;
mod packet_flow;

pub use crate::packet_capture::PacketCapture;
pub use crate::packet_capture::PacketOrigin;
pub use crate::packet_parse::get_datetime_of_packet;
pub use crate::packet_parse::try_parse_packet;
pub use crate::packet_parse::FlowIdentifier;
pub use crate::packet_flow::Flow;
pub use crate::packet_flow::FlowGroup;

pub use std::net::IpAddr;
pub use pcap::Device;
pub use pcap::Linktype;
