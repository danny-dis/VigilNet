//! DHCP Guard - Protection against DHCP-based attacks (TunnelVision)
//!
//! Detects and blocks malicious DHCP options that can hijack routing,
//! particularly Option 121 (Classless Static Route) and Option 249 (Microsoft Classless Static Route).

use crate::packet::{IpPacket, Protocol};
use tracing::{debug, info, warn};

const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpOptionCode {
    SubnetMask = 1,
    Router = 3,
    DomainNameServer = 6,
    DomainName = 15,
    StaticRoute = 33,
    LeaseTime = 51,
    MessageType = 53,
    ServerIdentifier = 54,
    RenewalTime = 58,
    RebindingTime = 59,
    ClasslessStaticRoute = 121,
    MicrosoftClasslessStaticRoute = 249,
    End = 255,
}

impl DhcpOptionCode {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::SubnetMask),
            3 => Some(Self::Router),
            6 => Some(Self::DomainNameServer),
            15 => Some(Self::DomainName),
            33 => Some(Self::StaticRoute),
            51 => Some(Self::LeaseTime),
            53 => Some(Self::MessageType),
            54 => Some(Self::ServerIdentifier),
            58 => Some(Self::RenewalTime),
            59 => Some(Self::RebindingTime),
            121 => Some(Self::ClasslessStaticRoute),
            249 => Some(Self::MicrosoftClasslessStaticRoute),
            255 => Some(Self::End),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpMessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
}

impl DhcpMessageType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Discover),
            2 => Some(Self::Offer),
            3 => Some(Self::Request),
            4 => Some(Self::Decline),
            5 => Some(Self::Ack),
            6 => Some(Self::Nak),
            7 => Some(Self::Release),
            8 => Some(Self::Inform),
            _ => None,
        }
    }
}

pub struct DhcpHeader<'a> {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: &'a [u8; 4],
    pub yiaddr: &'a [u8; 4],
    pub siaddr: &'a [u8; 4],
    pub giaddr: &'a [u8; 4],
    pub chaddr: &'a [u8; 16],
}

impl<'a> DhcpHeader<'a> {
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < 240 {
            return None;
        }

        Some(Self {
            op: data[0],
            htype: data[1],
            hlen: data[2],
            hops: data[3],
            xid: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            secs: u16::from_be_bytes([data[8], data[9]]),
            flags: u16::from_be_bytes([data[10], data[11]]),
            ciaddr: data[12..16].try_into().ok()?,
            yiaddr: data[16..20].try_into().ok()?,
            siaddr: data[20..24].try_into().ok()?,
            giaddr: data[24..28].try_into().ok()?,
            chaddr: data[28..44].try_into().ok()?,
        })
    }
}

pub struct DhcpGuard;

impl DhcpGuard {
    pub fn new() -> Self {
        Self
    }

    pub fn is_dhcp_packet(packet_data: &[u8]) -> bool {
        if let Some(ip) = IpPacket::parse(packet_data) {
            if let Protocol::Udp = ip.protocol {
                let payload = ip.payload;
                if payload.len() >= 4 {
                    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
                    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
                    return (src_port == DHCP_SERVER_PORT && dst_port == DHCP_CLIENT_PORT)
                        || (src_port == DHCP_CLIENT_PORT && dst_port == DHCP_SERVER_PORT);
                }
            }
        }
        false
    }

    pub fn inspect(packet_data: &[u8]) -> DhcpInspectionResult {
        if !Self::is_dhcp_packet(packet_data) {
            return DhcpInspectionResult::NotDhcp;
        }

        if let Some(ip) = IpPacket::parse(packet_data) {
            let payload = ip.payload;
            if payload.len() < 8 {
                return DhcpInspectionResult::Invalid;
            }

            let udp_data = &payload[8:];

            if let Some(header) = DhcpHeader::parse(udp_data) {
                let options = &udp_data[240..];

                for chunk in options.chunks(2) {
                    if chunk.is_empty() {
                        break;
                    }

                    let code = chunk[0];
                    if code == 255 {
                        break;
                    }

                    if chunk.len() < 2 {
                        break;
                    }

                    let len = chunk[1] as usize;

                    if code == 121 || code == 249 {
                        let route_count = Self::count_malicious_routes(&chunk[2..]);
                        if route_count > 0 {
                            warn!(
                                "DHCP ATTACK DETECTED: Option {} ({} routes) found - possible TunnelVision attack",
                                code,
                                route_count
                            );
                            return DhcpInspectionResult::ThreatDetected(DhcpThreat::ClasslessStaticRoute(route_count));
                        }
                    }

                    if len > options.len() - 2 {
                        break;
                    }
                }

                debug!("DHCP packet appears legitimate");
                return DhcpInspectionResult::Safe;
            }
        }

        DhcpInspectionResult::Invalid
    }

    fn count_malicious_routes(data: &[u8]) -> usize {
        let mut count = 0;
        let mut i = 0;

        while i < data.len() {
            if data[i] == 0 {
                i += 5;
                count += 1;
            } else {
                let mask_bits = data[i] as usize;
                let octets = (mask_bits + 7) / 8;
                i += 1 + 4 + octets;
                count += 1;
            }
        }

        count
    }

    pub fn validate_outbound(&self, packet_data: &[u8]) -> bool {
        match Self::inspect(packet_data) {
            DhcpInspectionResult::Safe | DhcpInspectionResult::NotDhcp => true,
            DhcpInspectionResult::ThreatDetected(threat) => {
                warn!("Blocking outbound DHCP packet: {:?}", threat);
                false
            }
            DhcpInspectionResult::Invalid => {
                debug!("Invalid DHCP packet dropped");
                false
            }
        }
    }

    pub fn validate_inbound(&self, packet_data: &[u8]) -> bool {
        match Self::inspect(packet_data) {
            DhcpInspectionResult::Safe | DhcpInspectionResult::NotDhcp => true,
            DhcpInspectionResult::ThreatDetected(threat) => {
                warn!("Blocking inbound DHCP packet: {:?}", threat);
                false
            }
            DhcpInspectionResult::Invalid => {
                debug!("Invalid DHCP packet dropped");
                false
            }
        }
    }
}

impl Default for DhcpGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub enum DhcpThreat {
    ClasslessStaticRoute(usize),
    RouterOption(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpInspectionResult {
    Safe,
    NotDhcp,
    Invalid,
    ThreatDetected(DhcpThreat),
}

impl DhcpInspectionResult {
    pub fn is_safe(&self) -> bool {
        matches!(self, Self::Safe | Self::NotDhcp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dhcp_option_codes() {
        assert_eq!(DhcpOptionCode::from_u8(121), Some(DhcpOptionCode::ClasslessStaticRoute));
        assert_eq!(DhcpOptionCode::from_u8(249), Some(DhcpOptionCode::MicrosoftClasslessStaticRoute));
        assert_eq!(DhcpOptionCode::from_u8(255), Some(DhcpOptionCode::End));
    }

    #[test]
    fn test_dhcp_message_types() {
        assert_eq!(DhcpMessageType::from_u8(1), Some(DhcpMessageType::Discover));
        assert_eq!(DhcpMessageType::from_u8(3), Some(DhcpMessageType::Request));
    }
}
