//! Group encryption using Signal's Sender Keys.
//!
//! Sender Keys allow efficient one-to-many encryption in channels.
//! Each sender maintains a chain key that all group members share.
//! When a member leaves, sender keys must be rotated for forward secrecy.

use libsignal_protocol::{
    create_sender_key_distribution_message, group_decrypt, group_encrypt,
    process_sender_key_distribution_message, SenderKeyDistributionMessage,
};
use rand::rngs::OsRng;
use uuid::Uuid;

use crate::session::user_address;
use crate::stores::SignalStores;

/// Create a distribution ID for a channel.
/// We use a deterministic UUID derived from the channel ID.
pub fn channel_distribution_id(channel_id: u32) -> Uuid {
    // Use UUID v5 (SHA-1 namespace) with our own namespace
    let namespace = Uuid::NAMESPACE_OID;
    Uuid::new_v5(&namespace, format!("voipc-channel-{}", channel_id).as_bytes())
}

/// Create a sender key distribution message for a channel.
/// This must be sent to all other channel members (encrypted pairwise).
pub async fn create_distribution_message(
    stores: &mut SignalStores,
    my_user_id: u32,
    channel_id: u32,
) -> anyhow::Result<Vec<u8>> {
    let address = user_address(my_user_id);
    let distribution_id = channel_distribution_id(channel_id);

    let msg = create_sender_key_distribution_message(
        &address,
        distribution_id,
        &mut stores.sender_key,
        &mut OsRng,
    )
    .await?;

    Ok(msg.serialized().to_vec())
}

/// Process a received sender key distribution message from another user.
pub async fn process_distribution_message(
    stores: &mut SignalStores,
    sender_user_id: u32,
    channel_id: u32,
    distribution_message_bytes: &[u8],
) -> anyhow::Result<()> {
    let sender_address = user_address(sender_user_id);
    let _distribution_id = channel_distribution_id(channel_id);

    let msg = SenderKeyDistributionMessage::try_from(distribution_message_bytes)?;

    process_sender_key_distribution_message(
        &sender_address,
        &msg,
        &mut stores.sender_key,
    )
    .await?;

    Ok(())
}

/// Encrypt a message for a channel using Sender Keys.
pub async fn encrypt_group_message(
    stores: &mut SignalStores,
    my_user_id: u32,
    channel_id: u32,
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let address = user_address(my_user_id);
    let distribution_id = channel_distribution_id(channel_id);

    let ciphertext = group_encrypt(
        &mut stores.sender_key,
        &address,
        distribution_id,
        plaintext,
        &mut OsRng,
    )
    .await?;

    Ok(ciphertext.serialized().to_vec())
}

/// Decrypt a channel message from a specific sender.
pub async fn decrypt_group_message(
    stores: &mut SignalStores,
    sender_user_id: u32,
    channel_id: u32,
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let sender_address = user_address(sender_user_id);
    let _distribution_id = channel_distribution_id(channel_id);

    let plaintext = group_decrypt(
        ciphertext,
        &mut stores.sender_key,
        &sender_address,
    )
    .await?;

    Ok(plaintext)
}

/// Reset sender key state for a channel (call when membership changes).
/// After this, you must create and distribute new sender keys.
pub async fn rotate_sender_key(
    stores: &mut SignalStores,
    my_user_id: u32,
    channel_id: u32,
) -> anyhow::Result<Vec<u8>> {
    // Remove old sender key by creating a fresh one
    // (libsignal creates a new chain on next create_sender_key_distribution_message)
    let distribution_id = channel_distribution_id(channel_id);
    let address = user_address(my_user_id);

    // Clear the old sender key record by storing a fresh one
    let msg = create_sender_key_distribution_message(
        &address,
        distribution_id,
        &mut stores.sender_key,
        &mut OsRng,
    )
    .await?;

    Ok(msg.serialized().to_vec())
}
