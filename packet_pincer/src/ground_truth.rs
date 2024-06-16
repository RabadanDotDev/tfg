use std::{
    cmp::{max, min, Ordering},
    collections::{hash_map::Entry, HashMap},
    error::Error,
    hash::Hash,
    net::IpAddr,
    path::PathBuf,
    rc::Rc,
};

use chrono::{DateTime, TimeDelta, Utc};
use etherparse::IpNumber;
use serde::Deserialize;

use crate::TransportFlow;

#[derive(Debug, Deserialize)]
struct GroundTruthRecord {
    low_ip: IpAddr,
    high_ip: IpAddr,
    transport_protocol: u8,
    timestamp_micro_start: i64,
    timestamp_micro_end: i64,
    label: String,
}

/// Collection of tags for flows given by the user and assumed to be true.
#[derive(Debug)]
pub struct GroundTruth {
    flows: HashMap<HostPair, SortedLabelList>,
}

impl GroundTruth {
    /// Try creating a GroundTruth instance from a given file
    pub fn from_file(file: PathBuf) -> Result<GroundTruth, Box<dyn Error>> {
        let mut reader = csv::Reader::from_path(file)?;
        let mut flows = HashMap::new();

        for result in reader.deserialize() {
            // Decode line
            let record: GroundTruthRecord = result?;
            let host_pair = HostPair::from(record.low_ip, record.high_ip, record.transport_protocol.into());
            let label = Label::from(
                record.timestamp_micro_start,
                record.timestamp_micro_end,
                record.label,
            )?;

            // Store label
            match flows.entry(host_pair) {
                Entry::Vacant(e) => {
                    e.insert(SortedLabelList::new(label));
                }
                Entry::Occupied(mut e) => e.get_mut().push(label)?,
            }
        }
        // Construct
        Ok(GroundTruth { flows })
    }

    /// Try finding a given label that matches the flow
    pub fn find_label(&self, flow: &TransportFlow) -> Option<Rc<str>> {
        match self.flows.get(&HostPair::from(
            flow.identifier.source_ip,
            flow.identifier.dest_ip,
            flow.identifier.transport_protocol
        )) {
            None => None,
            Some(list) => list.find_label(
                flow.flow_times.first_packet_time,
                flow.flow_times.last_packet_time,
            ),
        }
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
struct HostPair{
    lower_ip: IpAddr,
    higher_ip: IpAddr,
    transport_protocol: IpNumber,
}

impl HostPair {
    fn from(lower_ip: IpAddr, higher_ip: IpAddr, transport_protocol: IpNumber) -> HostPair {
        HostPair{
            lower_ip,
            higher_ip, 
            transport_protocol
        }
    }
}

#[derive(Debug)]
struct SortedLabelList(Vec<Label>);

impl SortedLabelList {
    fn push(&mut self, label: Label) -> Result<(), Box<dyn Error>> {
        let pos = self
            .0
            .binary_search_by_key(&label.end, |v| v.start)
            .unwrap_or_else(|e| e);

        // Check we dont overlap with previous
        if pos != 0 {
            if let Some(element) = self.0.get(pos - 1) {
                if label.start <= element.end {
                    return Err("Timestamps intervals between two hosts cannot overlap.".into());
                }
            }
        }

        // Check we dont overlap with the next
        if let Some(element) = self.0.get(pos) {
            if element.start <= label.end {
                return Err("Timestamps intervals between two hosts cannot overlap.".into());
            }
        }

        // Insert
        self.0.insert(pos, label);
        Ok(())
    }

    fn find_overlap_indicies(
        &self,
        first_time: DateTime<Utc>,
        last_time: DateTime<Utc>,
    ) -> Option<(usize, usize)> {
        // Find left overlap
        let mut previous = self
            .0
            .binary_search_by_key(&first_time, |v| v.start)
            .unwrap_or_else(|e| e);
        if previous != 0 {
            if let Some(element) = self.0.get(previous - 1) {
                if first_time <= element.end {
                    previous -= 1;
                }
            }
        };

        // Find right overlap
        let mut next = self
            .0
            .binary_search_by_key(&last_time, |v| v.end)
            .unwrap_or_else(|e| e);
        match self.0.get(next) {
            Some(element) => {
                if last_time < element.start {
                    if next == 0 {
                        return None;
                    } else {
                        next -= 1;
                    }
                }
            }
            None => {
                if next == 0 {
                    return None;
                } else {
                    next -= 1;
                }
            }
        }

        if next < previous {
            None
        } else {
            Some((previous, next))
        }
    }

    fn find_label(&self, first_time: DateTime<Utc>, last_time: DateTime<Utc>) -> Option<Rc<str>> {
        let (first, second) = self.find_overlap_indicies(first_time, last_time)?;

        // Find the label that overlaps the most
        let (label, _overlap) = self.0[first..second + 1]
            .iter()
            .map(|label| (label, label.compute_overlap(first_time, last_time)))
            .max_by_key(|pair| pair.1)?;

        Some(label.label.clone())
    }
}

impl SortedLabelList {
    fn new(label: Label) -> SortedLabelList {
        SortedLabelList(vec![label])
    }
}

/// # Invariants
/// start <= end
#[derive(Eq, Debug)]
struct Label {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    label: Rc<str>,
}

impl PartialOrd for Label {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.end < other.start {
            // The interval is previous to the other
            Some(Ordering::Less)
        } else if other.end < self.start {
            // The interval is posterior to the other
            Some(Ordering::Greater)
        } else {
            // There is an overlap between the intervals
            None
        }
    }
}

impl PartialEq for Label {
    fn eq(&self, other: &Self) -> bool {
        self.start == other.start && self.end == other.end
    }
}

impl Label {
    /// Creates a Label. timestamp_micro_start should be less or equal to timestamp_micro_end
    fn from(
        timestamp_micro_start: i64,
        timestamp_micro_end: i64,
        label: String,
    ) -> Result<Label, Box<dyn Error>> {
        let start = DateTime::from_timestamp_micros(timestamp_micro_start)
            .ok_or::<Box<dyn Error>>("Invalid timestamp".into())?;
        let end = DateTime::from_timestamp_micros(timestamp_micro_end)
            .ok_or::<Box<dyn Error>>("Invalid timestamp".into())?;

        let label: Rc<str> = Rc::from(label);

        if end < start {
            return Err("End timestamp cannot be previous than start timestamp".into());
        }

        Ok(Label { start, end, label })
    }

    fn compute_overlap(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> TimeDelta {
        if self.end < start || end < self.start {
            TimeDelta::microseconds(0)
        } else {
            let overlap_start = max(self.start, start);
            let overlap_end = min(self.end, end);
            overlap_end - overlap_start
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sorted_label_list_add_sorted() {
        let mut list = SortedLabelList::new(Label::from(2, 3, " ".to_string()).unwrap());
        list.push(Label::from(0, 1, " ".to_string()).unwrap())
            .unwrap();
        assert_eq!(
            list.0.get(0).unwrap().start,
            DateTime::from_timestamp_micros(0).unwrap()
        );
    }

    #[test]
    #[rustfmt::skip]
    fn test_sorted_label_list_prevents_overlap() {
        let mut list = SortedLabelList::new(Label::from(10, 20, " ".to_string()).unwrap());

        // Overlap with one that starts before
        assert!(list.push(Label::from(0, 10, " ".to_string()).unwrap()).is_err());
        assert!(list.push(Label::from(0, 15, " ".to_string()).unwrap()).is_err());
        assert!(list.push(Label::from(0, 20, " ".to_string()).unwrap()).is_err());
        assert!(list.push(Label::from(0, 25, " ".to_string()).unwrap()).is_err());

        // Overlap with one that starts after
        assert!(list.push(Label::from(05, 30, " ".to_string()).unwrap()).is_err());
        assert!(list.push(Label::from(10, 30, " ".to_string()).unwrap()).is_err());
        assert!(list.push(Label::from(15, 30, " ".to_string()).unwrap()).is_err());
        assert!(list.push(Label::from(20, 30, " ".to_string()).unwrap()).is_err());
    }

    #[test]
    #[rustfmt::skip]
    fn test_overlap_indicies() {
        let mut list = SortedLabelList::new(Label::from(01, 10, " ".to_string()).unwrap());
        list.push(Label::from(20, 30, " ".to_string()).unwrap())
            .unwrap();
        list.push(Label::from(40, 50, " ".to_string()).unwrap())
            .unwrap();

        // Test different empty points
        assert_eq!(list.find_overlap_indicies(DateTime::from_timestamp_micros(00).unwrap(), DateTime::from_timestamp_micros(00).unwrap()), None);
        assert_eq!(list.find_overlap_indicies(DateTime::from_timestamp_micros(11).unwrap(), DateTime::from_timestamp_micros(19).unwrap()), None);
        assert_eq!(list.find_overlap_indicies(DateTime::from_timestamp_micros(31).unwrap(), DateTime::from_timestamp_micros(39).unwrap()), None);
        assert_eq!(list.find_overlap_indicies(DateTime::from_timestamp_micros(51).unwrap(), DateTime::from_timestamp_micros(55).unwrap()), None);

        // Test extending from the left 
        assert_eq!(list.find_overlap_indicies(DateTime::from_timestamp_micros(00).unwrap(), DateTime::from_timestamp_micros(01).unwrap()), Some((0, 0))); 
        assert_eq!(list.find_overlap_indicies(DateTime::from_timestamp_micros(00).unwrap(), DateTime::from_timestamp_micros(05).unwrap()), Some((0, 0))); 
        assert_eq!(list.find_overlap_indicies(DateTime::from_timestamp_micros(00).unwrap(), DateTime::from_timestamp_micros(10).unwrap()), Some((0, 0))); 
        assert_eq!(list.find_overlap_indicies(DateTime::from_timestamp_micros(00).unwrap(), DateTime::from_timestamp_micros(15).unwrap()), Some((0, 0)));

        assert_eq!(list.find_overlap_indicies(DateTime::from_timestamp_micros(00).unwrap(), DateTime::from_timestamp_micros(20).unwrap()), Some((0, 1))); 
        assert_eq!(list.find_overlap_indicies(DateTime::from_timestamp_micros(00).unwrap(), DateTime::from_timestamp_micros(25).unwrap()), Some((0, 1))); 
        assert_eq!(list.find_overlap_indicies(DateTime::from_timestamp_micros(00).unwrap(), DateTime::from_timestamp_micros(30).unwrap()), Some((0, 1))); 
        assert_eq!(list.find_overlap_indicies(DateTime::from_timestamp_micros(00).unwrap(), DateTime::from_timestamp_micros(35).unwrap()), Some((0, 1)));

        assert_eq!(list.find_overlap_indicies(DateTime::from_timestamp_micros(00).unwrap(), DateTime::from_timestamp_micros(40).unwrap()), Some((0, 2))); 
        assert_eq!(list.find_overlap_indicies(DateTime::from_timestamp_micros(00).unwrap(), DateTime::from_timestamp_micros(45).unwrap()), Some((0, 2))); 
        assert_eq!(list.find_overlap_indicies(DateTime::from_timestamp_micros(00).unwrap(), DateTime::from_timestamp_micros(50).unwrap()), Some((0, 2))); 
        assert_eq!(list.find_overlap_indicies(DateTime::from_timestamp_micros(00).unwrap(), DateTime::from_timestamp_micros(55).unwrap()), Some((0, 2)));

        // Test extending from the right 
        assert_eq!(list.find_overlap_indicies(DateTime::from_timestamp_micros(50).unwrap(), DateTime::from_timestamp_micros(55).unwrap()), Some((2, 2))); 
        assert_eq!(list.find_overlap_indicies(DateTime::from_timestamp_micros(45).unwrap(), DateTime::from_timestamp_micros(55).unwrap()), Some((2, 2))); 
        assert_eq!(list.find_overlap_indicies(DateTime::from_timestamp_micros(40).unwrap(), DateTime::from_timestamp_micros(55).unwrap()), Some((2, 2))); 
        assert_eq!(list.find_overlap_indicies(DateTime::from_timestamp_micros(35).unwrap(), DateTime::from_timestamp_micros(55).unwrap()), Some((2, 2)));

        assert_eq!(list.find_overlap_indicies(DateTime::from_timestamp_micros(30).unwrap(), DateTime::from_timestamp_micros(55).unwrap()), Some((1, 2))); 
        assert_eq!(list.find_overlap_indicies(DateTime::from_timestamp_micros(25).unwrap(), DateTime::from_timestamp_micros(55).unwrap()), Some((1, 2))); 
        assert_eq!(list.find_overlap_indicies(DateTime::from_timestamp_micros(20).unwrap(), DateTime::from_timestamp_micros(55).unwrap()), Some((1, 2))); 
        assert_eq!(list.find_overlap_indicies(DateTime::from_timestamp_micros(15).unwrap(), DateTime::from_timestamp_micros(55).unwrap()), Some((1, 2)));

        assert_eq!(list.find_overlap_indicies(DateTime::from_timestamp_micros(10).unwrap(), DateTime::from_timestamp_micros(55).unwrap()), Some((0, 2))); 
        assert_eq!(list.find_overlap_indicies(DateTime::from_timestamp_micros(05).unwrap(), DateTime::from_timestamp_micros(55).unwrap()), Some((0, 2))); 
        assert_eq!(list.find_overlap_indicies(DateTime::from_timestamp_micros(01).unwrap(), DateTime::from_timestamp_micros(55).unwrap()), Some((0, 2))); 
        assert_eq!(list.find_overlap_indicies(DateTime::from_timestamp_micros(00).unwrap(), DateTime::from_timestamp_micros(55).unwrap()), Some((0, 2)));
    }

    #[test]
    #[rustfmt::skip]
    fn test_find_overlap_indicies() {
        let mut list = SortedLabelList::new(Label::from(01, 10, "first".to_string()).unwrap());
        list.push(Label::from(20, 30, "second".to_string()).unwrap())
            .unwrap();
        list.push(Label::from(40, 51, "third".to_string()).unwrap())
            .unwrap();

        // No match
        assert_eq!(list.find_label(DateTime::from_timestamp_micros(00).unwrap(), DateTime::from_timestamp_micros(00).unwrap()), None);

        // Exact match
        assert_eq!(list.find_label(DateTime::from_timestamp_micros(01).unwrap(), DateTime::from_timestamp_micros(10).unwrap()).unwrap(), "first".into());

        // Partial left match
        assert_eq!(list.find_label(DateTime::from_timestamp_micros(00).unwrap(), DateTime::from_timestamp_micros(05).unwrap()).unwrap(), "first".into());

        // Partial right match
        assert_eq!(list.find_label(DateTime::from_timestamp_micros(05).unwrap(), DateTime::from_timestamp_micros(15).unwrap()).unwrap(), "first".into());

        // Bigger/inside match
        assert_eq!(list.find_label(DateTime::from_timestamp_micros(05).unwrap(), DateTime::from_timestamp_micros(5).unwrap()).unwrap(), "first".into());
        assert_eq!(list.find_label(DateTime::from_timestamp_micros(0).unwrap(), DateTime::from_timestamp_micros(15).unwrap()).unwrap(), "first".into());

        // Multiple matches
        assert_eq!(list.find_label(DateTime::from_timestamp_micros(00).unwrap(), DateTime::from_timestamp_micros(20).unwrap()).unwrap(), "first".into());
        assert_eq!(list.find_label(DateTime::from_timestamp_micros(00).unwrap(), DateTime::from_timestamp_micros(30).unwrap()).unwrap(), "second".into());
        assert_eq!(list.find_label(DateTime::from_timestamp_micros(00).unwrap(), DateTime::from_timestamp_micros(60).unwrap()).unwrap(), "third".into());

    }
}
