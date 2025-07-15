//! Minimal test to check if basic operations work

use http3::{
    quic::{
        connection::{Connection, ConnectionRole},
        packet::ConnectionId,
        transport::TransportParameters,
    },
    error::Result,
};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== Minimal Test ===");
    
    // Create basic components
    let cid = ConnectionId::random(8)?;
    println!("Created connection ID: {:02x?}", cid.as_bytes());
    
    let addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let params = TransportParameters::default();
    
    // Create a connection
    let conn = Connection::new(
        ConnectionRole::Client,
        cid.clone(),
        cid.clone(),
        addr,
        params,
    )?;
    
    println!("Created connection with state: {:?}", conn.state());
    println!("Is established: {}", conn.is_established());
    
    Ok(())
}