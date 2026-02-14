//! Circuit Protocol Codec
//!
//! Implements the libp2p RequestResponse codec for circuit cells.

use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::{Codec, ProtocolName};
use std::io;
use vigilnet_crypto::onion::CircuitCell;

/// Circuit protocol name
#[derive(Debug, Clone)]
pub struct CircuitProtocol;

impl ProtocolName for CircuitProtocol {
    fn protocol_name(&self) -> &[u8] {
        b"/vigilnet/circuit/1.0.0"
    }
}

/// Codec for circuit cells
#[derive(Clone, Default)]
pub struct CircuitCodec;

#[async_trait]
impl Codec for CircuitCodec {
    type Protocol = CircuitProtocol;
    type Request = CircuitCell;
    type Response = CircuitCell;

    async fn read_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_length_prefixed(io).await
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_length_prefixed(io).await
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_length_prefixed(io, req).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_length_prefixed(io, res).await
    }
}

/// Read length-prefixed CircuitCell
async fn read_length_prefixed<T>(io: &mut T) -> io::Result<CircuitCell>
where
    T: AsyncRead + Unpin + Send,
{
    use futures::AsyncReadExt;

    // Read length (u32 big endian)
    let mut len_bytes = [0u8; 4];
    io.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;

    if len > 1024 * 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Cell too large",
        ));
    }

    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;

    CircuitCell::from_bytes(&buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

/// Write length-prefixed CircuitCell
async fn write_length_prefixed<T>(io: &mut T, cell: CircuitCell) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    let bytes = cell.to_bytes();
    let len = bytes.len() as u32;

    io.write_all(&len.to_be_bytes()).await?;
    io.write_all(&bytes).await?;
    io.flush().await?;

    Ok(())
}
