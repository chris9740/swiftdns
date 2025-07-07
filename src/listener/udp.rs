use anyhow::Result;
use hickory_proto::{
    op::{Message, ResponseCode},
    serialize::binary::{BinDecodable as _, BinEncodable as _},
};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::UdpSocket;

use crate::{
    blocking::create_response_base,
    listener::utils::is_local_ip,
    listener::{DnsContext, MessageResult},
};

pub async fn start_udp(addr: &SocketAddr, ctx: Arc<DnsContext>) -> Result<()> {
    let socket = UdpSocket::bind(addr).await?;

    loop {
        let mut buf = [0; 512];
        let (amt, src) = socket.recv_from(&mut buf).await?;

        if !is_local_ip(&src.ip()) {
            tracing::warn!(src=%src, "Received non-local UDP query");
            continue;
        }

        if let Ok(message) = Message::from_bytes(&buf[..amt]) {
            match ctx.handle_message(&message).await {
                Ok(MessageResult::Response(response)) => {
                    socket.send_to(&response.to_bytes()?, src).await?;
                }
                Ok(MessageResult::Drop) => {
                    // Drop strategy - no response sent (this is intentional)
                }
                Err(_) => {
                    let mut error_response = create_response_base(&message);
                    error_response.set_response_code(ResponseCode::ServFail);
                    socket.send_to(&error_response.to_bytes()?, src).await?;
                }
            }
        } else {
            tracing::warn!(src=%src, "Received invalid DNS message, ignoring");
        }
    }
}
