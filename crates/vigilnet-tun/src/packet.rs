//! IP packet parsing and handling
//!
//! Provides zero-copy packet parsing for IPv4/IPv6 with efficient
//! header extraction and protocol identification.

use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Icmp,
    Tcp,
    Udp,
    Icmpv6,
    Unknown(u8),
}

impl Protocol {
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => Protocol::Icmp,
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            58 => Protocol::Icmpv6,
            _ => Protocol::Unknown(value),
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Protocol::Icmp => 1,
            Protocol::Tcp => 6,
            Protocol::Udp => 17,
            Protocol::Icmpv6 => 58,
            Protocol::Unknown(v) => v,
        }
    }
}

#[derive(Debug, Clone)]
pub struct IpPacket<'a> {
    pub version: IpVersion,
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub protocol: Protocol,
    pub payload: &'a [u8],
    raw: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl IpAddr {
    pub fn is_private(&self) -> bool {
        match self {
            IpAddr::V4(ip) => {
                let octets = ip.octets();
                octets[0] == 10
                    || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                    || (octets[0] == 192 && octets[1] == 168)
                    || (octets[0] == 127)
            }
            IpAddr::V6(ip) => {
                let segments = ip.segments();
                segments[0] == 0xfc00 || segments[0] == 0xfe80
            }
        }
    }

    pub fn is_loopback(&self) -> bool {
        match self {
            IpAddr::V4(ip) => ip.is_loopback(),
            IpAddr::V6(ip) => ip.is_loopback(),
        }
    }

    pub fn is_multicast(&self) -> bool {
        match self {
            IpAddr::V4(ip) => ip.is_multicast(),
            IpAddr::V6(ip) => ip.is_multicast(),
        }
    }
}

impl<'a> IpPacket<'a> {
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }

        let version = (data[0] >> 4) & 0x0F;

        match version {
            4 => Self::parse_v4(data),
            6 => Self::parse_v6(data),
            _ => None,
        }
    }

    fn parse_v4(data: &'a [u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }

        let ihl = ((data[0] & 0x0F) as usize) * 4;
        if data.len() < ihl {
            return None;
        }

        let src_addr = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let dst_addr = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
        let protocol = Protocol::from_u8(data[9]);

        Some(Self {
            version: IpVersion::V4,
            src_addr: IpAddr::V4(src_addr),
            dst_addr: IpAddr::V4(dst_addr),
            protocol,
            payload: &data[ihl..],
            raw: data,
        })
    }

    fn parse_v6(data: &'a [u8]) -> Option<Self> {
        if data.len() < 40 {
            return None;
        }

        let src_addr = Ipv6Addr::new(
            u16::from_be_bytes([data[8], data[9]]),
            u16::from_be_bytes([data[10], data[11]]),
            u16::from_be_bytes([data[12], data[13]]),
            u16::from_be_bytes([data[14], data[15]]),
            u16::from_be_bytes([data[16], data[17]]),
            u16::from_be_bytes([data[18], data[19]]),
            u16::from_be_bytes([data[20], data[21]]),
            u16::from_be_bytes([data[22], data[23]]),
        );

        let dst_addr = Ipv6Addr::new(
            u16::from_be_bytes([data[24], data[25]]),
            u16::from_be_bytes([data[26], data[27]]),
            u16::from_be_bytes([data[28], data[29]]),
            u16::from_be_bytes([data[30], data[31]]),
            u16::from_be_bytes([data[32], data[33]]),
            u16::from_be_bytes([data[34], data[35]]),
            u16::from_be_bytes([data[36], data[37]]),
            u16::from_be_bytes([data[38], data[39]]),
        );

        let protocol = Protocol::from_u8(data[6]);

        Some(Self {
            version: IpVersion::V6,
            src_addr: IpAddr::V6(src_addr),
            dst_addr: IpAddr::V6(dst_addr),
            protocol,
            payload: &data[40..],
            raw: data,
        })
    }

    pub fn src_addr_str(&self) -> String {
        match &self.src_addr {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => ip.to_string(),
        }
    }

    pub fn dst_addr_str(&self) -> String {
        match &self.dst_addr {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => ip.to_string(),
        }
    }

    pub fn protocol_name(&self) -> &'static str {
        match self.protocol {
            Protocol::Icmp => "ICMP",
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
            Protocol::Icmpv6 => "ICMPv6",
            Protocol::Unknown(_) => "Unknown",
        }
    }

    pub fn header_len(&self) -> usize {
        match self.version {
            IpVersion::V4 => ((self.raw[0] & 0x0F) as usize) * 4,
            IpVersion::V6 => 40,
        }
    }

    pub fn total_len(&self) -> usize {
        match self.version {
            IpVersion::V4 if self.raw.len() >= 2 => {
                u16::from_be_bytes([self.raw[2], self.raw[3]]) as usize
            }
            IpVersion::V6 if self.raw.len() >= 4 => {
                u16::from_be_bytes([self.raw[4], self.raw[5]]) as usize + 40
            }
            _ => self.raw.len(),
        }
    }

    pub fn is_fragment(&self) -> bool {
        match self.version {
            IpVersion::V4 if self.raw.len() >= 6 => {
                let flags = self.raw[6];
                let frag_offset = u16::from_be_bytes([self.raw[6] & 0x1F, self.raw[7]]);
                (flags & 0x20) != 0 || frag_offset != 0
            }
            IpVersion::V6 if self.raw.len() >= 4 => {
                let payload_len = u16::from_be_bytes([self.raw[4], self.raw[5]]);
                let frag_header_offset = 40 + 8;
                self.raw.len() > frag_header_offset
                    && &self.raw[40..42] == &[0x11, 0x00]
            }
            _ => false,
        }
    }

    pub fn raw_packet(&self) -> &'a [u8] {
        self.raw
    }

    pub fn is_valid(&self) -> bool {
        !self.raw.is_empty()
            && match self.version {
                IpVersion::V4 => self.raw.len() >= 20,
                IpVersion::V6 => self.raw.len() >= 40,
            }
    }
}

pub struct PacketBuffer {
    buffer: Vec<u8>,
    offset: usize,
}

impl PacketBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: vec![0u8; capacity],
            offset: 0,
        }
    }

    pub fn from_vec(vec: Vec<u8>) -> Self {
        Self { buffer: vec, offset: 0 }
    }

    pub fn push(&mut self, data: &[u8]) -> usize {
        let start = self.offset;
        if self.offset + data.len() <= self.buffer.len() {
            self.buffer[start..start + data.len()].copy_from_slice(data);
            self.offset += data.len();
            start
        } else {
            self.buffer.extend_from_slice(data);
            self.offset = self.buffer.len();
            start
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buffer[..self.offset]
    }

    pub fn clear(&mut self) {
        self.offset = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4() {
        let mut data = vec![0u8; 40];
        data[0] = 0x45;
        data[9] = 6;
        data[12..16].copy_from_slice(&[192, 168, 1, 1]);
        data[16..20].copy_from_slice(&[10, 0, 0, 1]);
        data[2] = 0x00;
        data[3] = 0x28;

        let packet = IpPacket::parse(&data).unwrap();
        assert_eq!(packet.version, IpVersion::V4);
        assert_eq!(packet.protocol, Protocol::Tcp);
        assert_eq!(packet.src_addr_str(), "192.168.1.1");
        assert_eq!(packet.dst_addr_str(), "10.0.0.1");
        assert!(packet.is_valid());
    }

    #[test]
    fn test_parse_ipv6() {
        let mut data = vec![0u8; 60];
        data[0] = 0x60;
        data[6] = 6;
        data[8..24].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]);
        data[24..40].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ]);

        let packet = IpPacket::parse(&data).unwrap();
        assert_eq!(packet.version, IpVersion::V6);
        assert_eq!(packet.protocol, Protocol::Tcp);
    }

    #[test]
    fn test_private_ip_v4() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(ip.is_private());

        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(!ip.is_private());
    }
}
