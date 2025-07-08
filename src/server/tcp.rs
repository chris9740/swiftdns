use anyhow::Result;
use hickory_proto::{
    op::{Message, ResponseCode},
    serialize::binary::{BinDecodable as _, BinEncodable as _},
};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
};

use crate::{
    blocking::create_response_base,
    server::{utils::is_local_ip, DnsContext, MessageResult},
};

pub async fn start_tcp(addr: &SocketAddr, ctx: Arc<DnsContext>) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;

    loop {
        let (mut stream, peer) = listener.accept().await?;
        if !is_local_ip(&peer.ip()) {
            tracing::warn!(peer=%peer, "Received non-local TCP query");
            continue;
        }
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_tcp(&mut stream, ctx).await {
                tracing::error!(error=?e, "TCP handler error");
            }
        });
    }
}

async fn handle_tcp(stream: &mut tokio::net::TcpStream, ctx: Arc<DnsContext>) -> Result<()> {
    let mut lenb = [0u8; 2];

    stream.read_exact(&mut lenb).await?;

    let len = u16::from_be_bytes(lenb) as usize;
    let mut buf = vec![0u8; len];

    stream.read_exact(&mut buf).await?;

    if let Ok(message) = Message::from_bytes(&buf) {
        let response = match ctx.handle_message(&message).await {
            Ok(MessageResult::Response(r)) => r,
            Ok(MessageResult::Drop) => return Ok(()),
            Err(_) => {
                let mut response = create_response_base(&message);
                response.set_response_code(ResponseCode::ServFail);
                response
            }
        };

        let resp_bytes = response.to_bytes()?;
        let resp_bytes_len = resp_bytes.len() as u16;

        stream.write_all(&resp_bytes_len.to_be_bytes()).await?;
        stream.write_all(&resp_bytes).await?;
    }
    Ok(())
}
