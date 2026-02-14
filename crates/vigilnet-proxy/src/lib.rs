//! SOCKS5 Proxy for VigilNet
//!
//! Handles incoming SOCKS5 connections and routes them through the VigilNet network.
//! Supports Signal Protocol E2EE for encrypting all traffic between client and exit node.

pub mod server;

pub use server::{ProxyError, SocksProxy};
