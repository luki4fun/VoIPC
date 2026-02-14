// Quick integration test: connect to the running server, authenticate, receive channel list
// Run with: cargo run -p voipc-server --example test_client

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use voipc_protocol::codec::{
    decode_server_msg, encode_client_msg, try_decode_frame, PROTOCOL_VERSION,
};
use voipc_protocol::messages::{ClientMessage, ServerMessage};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("crypto provider");

    // TCP connect
    let tcp = tokio::net::TcpStream::connect("127.0.0.1:9987").await?;
    println!("[OK] TCP connected to 127.0.0.1:9987");

    // TLS handshake
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name =
        rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap();
    let mut tls = connector.connect(server_name, tcp).await?;
    println!("[OK] TLS handshake complete");

    // Send Authenticate
    let auth = ClientMessage::Authenticate {
        username: "TestUser".into(),
        protocol_version: PROTOCOL_VERSION,
        identity_key: None,
        prekey_bundle: None,
    };
    tls.write_all(&encode_client_msg(&auth)?).await?;
    println!("[OK] Sent Authenticate message");

    // Read all initial responses (auth + channel list + user list)
    let mut buf = bytes::BytesMut::with_capacity(4096);
    read_and_print(&mut tls, &mut buf).await?;

    // Join channel 0 (General)
    let join = ClientMessage::JoinChannel { channel_id: 0, password: None };
    tls.write_all(&encode_client_msg(&join)?).await?;
    println!("\n[OK] Sent JoinChannel(0)");

    read_and_print(&mut tls, &mut buf).await?;

    // Send Ping
    let ping = ClientMessage::Ping { timestamp: 12345 };
    tls.write_all(&encode_client_msg(&ping)?).await?;
    println!("\n[OK] Sent Ping");

    read_and_print(&mut tls, &mut buf).await?;

    // Disconnect
    let disc = ClientMessage::Disconnect;
    tls.write_all(&encode_client_msg(&disc)?).await?;
    println!("\n[OK] Sent Disconnect");
    println!("\n=== All tests passed! ===");

    Ok(())
}

async fn read_and_print(
    tls: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    buf: &mut bytes::BytesMut,
) -> Result<(), Box<dyn std::error::Error>> {
    // Read with timeout — keep reading until no more data arrives within 500ms
    loop {
        match timeout(Duration::from_millis(500), tls.read_buf(buf)).await {
            Ok(Ok(0)) => {
                println!("[ERR] Server closed connection");
                break;
            }
            Ok(Ok(_)) => {
                // Process all complete frames
                while let Some(payload) = try_decode_frame(buf)? {
                    let msg = decode_server_msg(&payload)?;
                    print_message(&msg);
                }
            }
            Ok(Err(e)) => {
                println!("[ERR] Read error: {}", e);
                break;
            }
            Err(_) => break, // Timeout — no more data
        }
    }
    Ok(())
}

fn print_message(msg: &ServerMessage) {
    match msg {
        ServerMessage::Authenticated {
            user_id,
            session_id,
            udp_port,
            ..
        } => {
            println!(
                "[OK] Authenticated: user_id={}, session_id={}, udp_port={}",
                user_id, session_id, udp_port
            );
        }
        ServerMessage::AuthError { reason } => {
            println!("[ERR] Auth failed: {}", reason);
        }
        ServerMessage::ChannelList { channels } => {
            println!("[OK] Received channel list ({} channels):", channels.len());
            for ch in channels {
                println!(
                    "     #{} {} - {} (users: {}/{}){}",
                    ch.channel_id, ch.name, ch.description, ch.user_count, ch.max_users,
                    if ch.has_password { " [PASSWORD]" } else { "" }
                );
            }
        }
        ServerMessage::UserList { channel_id, users } => {
            println!(
                "[OK] User list for channel {} ({} users):",
                channel_id,
                users.len()
            );
            for u in users {
                println!("     - {} (id={})", u.username, u.user_id);
            }
        }
        ServerMessage::Pong { timestamp } => {
            println!("[OK] Pong received (timestamp={})", timestamp);
        }
        ServerMessage::ChannelChatMessage {
            channel_id,
            user_id,
            username,
            content,
            ..
        } => {
            println!(
                "[CHAT] #{} <{}({})>: {}",
                channel_id, username, user_id, content
            );
        }
        ServerMessage::DirectChatMessage {
            from_user_id,
            from_username,
            to_user_id,
            content,
            ..
        } => {
            println!(
                "[DM] {}({}) -> {}: {}",
                from_username, from_user_id, to_user_id, content
            );
        }
        other => {
            println!("[INFO] Received: {:?}", other);
        }
    }
}

#[derive(Debug)]
struct NoCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
