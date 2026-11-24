//! Group encryption using Signal's Sender Keys.
//!
//! Sender Keys allow efficient one-to-many encryption in channels.
//! Each sender maintains a chain key that all group members share.
//! When a member leaves, sender keys must be rotated for forward secrecy.

use libsignal_protocol::{
    create_sender_key_distribution_message, group_decrypt, group_encrypt,
    process_sender_key_distribution_message, SenderKeyDistributionMessage, SenderKeyMessage,
    SignalProtocolError,
};
use uuid::Uuid;

use crate::session::user_address;
use crate::stores::SignalStores;

/// Create a distribution ID for a channel.
/// We use a deterministic UUID derived from the channel ID.
pub fn channel_distribution_id(channel_id: u32) -> Uuid {
    // Use UUID v5 (SHA-1 namespace) with our own namespace
    let namespace = Uuid::NAMESPACE_OID;
    Uuid::new_v5(
        &namespace,
        format!("voipc-channel-{}", channel_id).as_bytes(),
    )
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
        &mut crate::rng(),
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

    process_sender_key_distribution_message(&sender_address, &msg, &mut stores.sender_key).await?;

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
        &mut crate::rng(),
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

/// Whether a decrypt failed for want of this writer's key, which may still come, and not
/// because the post can never open: a key from after it, a bad signature.
pub fn lacks_key(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<libsignal_protocol::SignalProtocolError>(),
        Some(libsignal_protocol::SignalProtocolError::NoSenderKeyState { .. })
    )
}

/// Decrypt a channel message from a specific sender.
///
/// `channel_id` is the channel the *server* said the message arrived in, and
/// it is checked rather than trusted: libsignal picks the chain by the id
/// inside the ciphertext, so without this a relay could re-label a message
/// from one channel as another and every client would believe it.
///
/// A message read once is refused after, with libsignal's own
/// `DuplicatedMessage(chain id, position)`, even once libsignal dropped the
/// chain's state and the same key brought it back afresh, where it would open
/// again for a relay replaying it (`VoipcSenderKeyStore::was_read`). It holds on
/// this connection, for the user id the relay names the sender by (stores.rs,
/// "What was read", has the two ways left). Every
/// caller takes that as it takes libsignal's duplicate: the live path rings and
/// shows nothing (`channel_state` `text_post`, `open_held`), the old path shows
/// its "decryption failed" line (native `handle_encrypted_channel_message`,
/// web `onEncryptedChannelMessage`). Only a message that opened counts as read.
pub async fn decrypt_group_message(
    stores: &mut SignalStores,
    sender_user_id: u32,
    channel_id: u32,
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let sender_address = user_address(sender_user_id);
    let distribution_id = channel_distribution_id(channel_id);

    let message = SenderKeyMessage::try_from(ciphertext)?;
    if message.distribution_id() != distribution_id {
        anyhow::bail!("message was encrypted for a different channel than it arrived in");
    }
    let (chain_id, iteration) = (message.chain_id(), message.iteration());
    if stores
        .sender_key
        .was_read(&sender_address, distribution_id, chain_id, iteration)
    {
        return Err(SignalProtocolError::DuplicatedMessage(chain_id, iteration).into());
    }

    let plaintext = group_decrypt(ciphertext, &mut stores.sender_key, &sender_address).await?;
    stores
        .sender_key
        .mark_read(&sender_address, distribution_id, chain_id, iteration);

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
        match Box::pin(fut)
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
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
        ready(process_distribution_message(
            receiver, sender_id, channel, &dist,
        ))
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

    /// Refused as libsignal refuses a message it has seen.
    fn is_duplicate(result: anyhow::Result<Vec<u8>>) -> bool {
        result.is_err_and(|e| {
            matches!(
                e.downcast_ref::<SignalProtocolError>(),
                Some(SignalProtocolError::DuplicatedMessage(..))
            )
        })
    }

    /// libsignal keeps five chains a writer, and a key it does not hold starts afresh at its
    /// position. A relay that kept the first chain's key hands it back once five newer pushed
    /// it out: a post read on it must not open again, though one not read yet still does.
    #[test]
    fn a_post_read_once_stays_read_when_its_chain_comes_back() {
        let (alice, bob) = (1, 2);
        let mut a = stores_for(alice);
        let mut b = stores_for(bob);
        let first = ready(create_distribution_message(&mut a, alice, 7)).unwrap();
        ready(process_distribution_message(&mut b, alice, 7, &first)).unwrap();
        let read = ready(encrypt_group_message(&mut a, alice, 7, b"read")).unwrap();
        let unread = ready(encrypt_group_message(&mut a, alice, 7, b"unread")).unwrap();
        assert_eq!(
            ready(decrypt_group_message(&mut b, alice, 7, &read)).unwrap(),
            b"read"
        );
        assert!(is_duplicate(ready(decrypt_group_message(
            &mut b, alice, 7, &read
        ))));
        for _ in 0..5 {
            forget_own_sender_key(&mut a, alice, 7);
            hand_over(&mut a, alice, &mut b, 7).unwrap();
        }
        assert!(lacks_key(
            &ready(decrypt_group_message(&mut b, alice, 7, &unread)).unwrap_err()
        ));
        ready(process_distribution_message(&mut b, alice, 7, &first)).unwrap();
        assert!(
            is_duplicate(ready(decrypt_group_message(&mut b, alice, 7, &read))),
            "a post read once opened again"
        );
        assert_eq!(
            ready(decrypt_group_message(&mut b, alice, 7, &unread)).unwrap(),
            b"unread"
        );
    }

    /// The same once the whole record went, as the store drops one past its limit: the key
    /// a `KeyWanted` brings back opens nothing read before.
    #[test]
    fn a_post_read_once_stays_read_when_its_record_went() {
        let (alice, bob) = (1, 2);
        let mut a = stores_for(alice);
        let mut b = stores_for(bob);
        let first = ready(create_distribution_message(&mut a, alice, 7)).unwrap();
        ready(process_distribution_message(&mut b, alice, 7, &first)).unwrap();
        let read = ready(encrypt_group_message(&mut a, alice, 7, b"read")).unwrap();
        ready(decrypt_group_message(&mut b, alice, 7, &read)).unwrap();
        b.sender_key
            .forget(&user_address(alice), channel_distribution_id(7));
        ready(process_distribution_message(&mut b, alice, 7, &first)).unwrap();
        assert!(
            is_duplicate(ready(decrypt_group_message(&mut b, alice, 7, &read))),
            "a post read once opened again"
        );
        // Another writer's post at the same chain position is theirs, not read
        let carol = 3;
        let mut c = stores_for(carol);
        hand_over(&mut c, carol, &mut b, 7).unwrap();
        let theirs = ready(encrypt_group_message(&mut c, carol, 7, b"theirs")).unwrap();
        assert_eq!(
            ready(decrypt_group_message(&mut b, carol, 7, &theirs)).unwrap(),
            b"theirs"
        );
    }

    /// Only a post that opened counts as read: one tried before its key came, or one whose
    /// signature fails, leaves its place open for the real one, as a held post's does.
    #[test]
    fn only_a_post_that_opened_counts_as_read() {
        let (alice, bob) = (1, 2);
        let mut a = stores_for(alice);
        let mut b = stores_for(bob);
        let dist = ready(create_distribution_message(&mut a, alice, 7)).unwrap();
        let post = ready(encrypt_group_message(&mut a, alice, 7, b"post")).unwrap();
        let early = ready(decrypt_group_message(&mut b, alice, 7, &post)).unwrap_err();
        assert!(lacks_key(&early), "{early}");
        ready(process_distribution_message(&mut b, alice, 7, &dist)).unwrap();
        let mut forged = post.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert!(ready(decrypt_group_message(&mut b, alice, 7, &forged)).is_err());
        assert_eq!(
            ready(decrypt_group_message(&mut b, alice, 7, &post)).unwrap(),
            b"post"
        );
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
