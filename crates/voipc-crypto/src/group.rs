//! Group encryption using Signal's Sender Keys.
//!
//! Sender Keys allow efficient one-to-many encryption in channels.
//! Each sender maintains a chain key that all group members share.
//! When a member leaves, sender keys must be rotated for forward secrecy.

use libsignal_protocol::{
    create_sender_key_distribution_message, group_decrypt, group_encrypt,
    process_sender_key_distribution_message, SenderKeyDistributionMessage, SenderKeyMessage,
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
///
/// `channel_id` is the channel the *server* said this key is for, and it is
/// checked rather than trusted: libsignal files the key under the id carried
/// inside the message, so without this a peer we share one channel with could
/// install a key for any other channel we are in.
pub async fn process_distribution_message(
    stores: &mut SignalStores,
    sender_user_id: u32,
    channel_id: u32,
    distribution_message_bytes: &[u8],
) -> anyhow::Result<()> {
    let sender_address = user_address(sender_user_id);
    let distribution_id = channel_distribution_id(channel_id);

    let msg = SenderKeyDistributionMessage::try_from(distribution_message_bytes)?;
    if msg.distribution_id()? != distribution_id {
        anyhow::bail!("sender key is for a different channel than the one it was sent in");
    }

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

/// Forget our own sender key for a channel, so the next message we send there
/// starts a fresh chain that has to be distributed again.
///
/// This is how a member leaving costs them the future: the chain key they hold
/// decrypts nothing sent after the rotation. Their old messages still decrypt
/// for everyone else — those chains are the senders' own and are untouched.
pub fn forget_own_sender_key(stores: &mut SignalStores, my_user_id: u32, channel_id: u32) {
    let address = user_address(my_user_id);
    stores
        .sender_key
        .forget(&address, channel_distribution_id(channel_id));
}

/// Decrypt a channel message from a specific sender.
///
/// `channel_id` is the channel the *server* said the message arrived in, and
/// it is checked rather than trusted: libsignal picks the chain by the id
/// inside the ciphertext, so without this a relay could re-label a message
/// from one channel as another and every client would believe it.
pub async fn decrypt_group_message(
    stores: &mut SignalStores,
    sender_user_id: u32,
    channel_id: u32,
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let sender_address = user_address(sender_user_id);
    let distribution_id = channel_distribution_id(channel_id);

    if SenderKeyMessage::try_from(ciphertext)?.distribution_id() != distribution_id {
        anyhow::bail!("message was encrypted for a different channel than it arrived in");
    }

    let plaintext = group_decrypt(
        ciphertext,
        &mut stores.sender_key,
        &sender_address,
    )
    .await?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stores::SignalStores;
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    /// Run a libsignal future to completion. Every store here is in memory, so
    /// it is ready on the first poll — the same assumption voipc-web makes,
    /// and cheaper than an async runtime this crate does not otherwise need.
    fn ready<T>(fut: impl Future<Output = T>) -> T {
        match Box::pin(fut).as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("in-memory stores never pend"),
        }
    }

    fn stores_for(user_id: u32) -> SignalStores {
        let identity = crate::generate_identity_key_pair();
        SignalStores::new(&identity, 1000 + user_id)
    }

    /// Hand `sender`'s key for `channel` to `receiver`, as the pairwise relay
    /// would — the envelope in between is not what these tests are about.
    fn hand_over(
        sender: &mut SignalStores,
        sender_id: u32,
        receiver: &mut SignalStores,
        channel: u32,
    ) -> anyhow::Result<()> {
        let dist = ready(create_distribution_message(sender, sender_id, channel))?;
        ready(process_distribution_message(receiver, sender_id, channel, &dist))
    }

    /// A relay that re-labels a message must not be believed: the channel is
    /// inside the ciphertext, and the one the server names has to match it.
    #[test]
    fn a_message_only_decrypts_in_the_channel_it_was_sent_in() {
        let (alice, bob) = (1, 2);
        let mut a = stores_for(alice);
        let mut b = stores_for(bob);
        hand_over(&mut a, alice, &mut b, 7).unwrap();

        let ciphertext = ready(encrypt_group_message(&mut a, alice, 7, b"hello")).unwrap();
        let plain = ready(decrypt_group_message(&mut b, alice, 7, &ciphertext)).unwrap();
        assert_eq!(plain, b"hello");

        // The same bytes, announced as another channel we are also in
        hand_over(&mut a, alice, &mut b, 9).unwrap();
        let err = ready(decrypt_group_message(&mut b, alice, 9, &ciphertext))
            .unwrap_err()
            .to_string();
        assert!(err.contains("different channel"), "{err}");
    }

    /// The same for a key: a peer we share one channel with cannot install a
    /// sender key for another channel by claiming it belongs there.
    #[test]
    fn a_sender_key_only_installs_for_the_channel_it_was_made_for() {
        let (alice, bob) = (1, 2);
        let mut a = stores_for(alice);
        let mut b = stores_for(bob);
        let dist = ready(create_distribution_message(&mut a, alice, 7)).unwrap();
        let err = ready(process_distribution_message(&mut b, alice, 9, &dist))
            .unwrap_err()
            .to_string();
        assert!(err.contains("different channel"), "{err}");
    }

    /// After a member leaves, the sender rotates: whoever processed the new
    /// key reads on, whoever holds only the old one does not.
    #[test]
    fn rotating_locks_out_the_chain_a_leaver_kept() {
        let (alice, bob, mallory) = (1u32, 2u32, 3u32);
        let mut a = stores_for(alice);
        let mut b = stores_for(bob);
        let mut m = stores_for(mallory);
        hand_over(&mut a, alice, &mut b, 7).unwrap();
        hand_over(&mut a, alice, &mut m, 7).unwrap();

        // Mallory leaves; alice rotates and re-distributes to the members left
        forget_own_sender_key(&mut a, alice, 7);
        hand_over(&mut a, alice, &mut b, 7).unwrap();

        let ciphertext = ready(encrypt_group_message(&mut a, alice, 7, b"after")).unwrap();
        assert_eq!(
            ready(decrypt_group_message(&mut b, alice, 7, &ciphertext)).unwrap(),
            b"after"
        );
        assert!(
            ready(decrypt_group_message(&mut m, alice, 7, &ciphertext)).is_err(),
            "a former member must not read what was sent after they left"
        );
    }
}
