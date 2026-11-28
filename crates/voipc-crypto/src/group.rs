//! Group encryption using Signal's Sender Keys.
//!
//! Sender Keys allow efficient one-to-many encryption in channels.
//! Each sender maintains a chain key that all group members share.
//! When a member leaves, sender keys must be rotated for forward secrecy.

use libsignal_protocol::{
    create_sender_key_distribution_message, group_decrypt, group_encrypt,
    process_sender_key_distribution_message, ProtocolAddress, SenderKeyDistributionMessage,
    SenderKeyMessage, SignalProtocolError,
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
/// A message read once is refused after (`open_once`), with libsignal's own
/// `DuplicatedMessage(chain id, position)`. Every caller takes that as it takes
/// libsignal's duplicate: the live path rings and shows nothing (`channel_state`
/// `text_post`, `open_held`), the old path shows its "decryption failed" line
/// (native `handle_encrypted_channel_message`, web `onEncryptedChannelMessage`).
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
    open_once(stores, &sender_address, &message, false).await
}

/// libsignal's `group_decrypt` of `message` from `sender`, which refuses a message read
/// before with libsignal's own `DuplicatedMessage(chain id, position)`, whatever libsignal
/// holds by then (stores.rs, "What was read"): once libsignal dropped the chain's state, or
/// the store its record, and the same key brought it back afresh; under another sender id
/// the relay names its writer by; and on a later connection that took over this one's
/// sessions (`KeptSessions`). Within the bounds there (`READ_CHAINS`, `READ_RUNS`). Only a
/// message that opened counts as read, by the key its chain signs with, from the state
/// libsignal opened it by. Both paths open by it: this module's (`decrypt_group_message`)
/// and the group key's (group_state/reader.rs `open`), which passes `by_writer`: its
/// sender's name is bound by the writer's blob, so a chain is kept read under it too
/// (`Signer::under`).
pub(crate) async fn open_once(
    stores: &mut SignalStores,
    sender: &ProtocolAddress,
    message: &SenderKeyMessage,
    by_writer: bool,
) -> anyhow::Result<Vec<u8>> {
    let (chain_id, iteration) = (message.chain_id(), message.iteration());
    let distribution_id = message.distribution_id();
    let signer = stores
        .sender_key
        .signer_of(sender, distribution_id, chain_id)?
        .map(|signer| {
            if by_writer {
                signer.under(sender.name())
            } else {
                signer
            }
        });
    if signer.is_some_and(|signer| stores.sender_key.was_read(&signer, iteration)) {
        return Err(SignalProtocolError::DuplicatedMessage(chain_id, iteration).into());
    }
    let plaintext = group_decrypt(message.serialized(), &mut stores.sender_key, sender).await?;
    // Opened by a state not found above: with nothing to keep it read by, not let through
    let Some(signer) = signer else {
        return Err(SignalProtocolError::InvalidSenderKeySession { distribution_id }.into());
    };
    stores.sender_key.mark_read(signer, iteration);
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

    /// A relay that names the writer under another id installs the same key in a new record
    /// (`ChannelKeying::find_session` moves the reader's session there, review 5): what was
    /// read on that chain stays read, by the key it signs with, and what was not still opens.
    #[test]
    fn a_post_read_once_stays_read_under_another_sender_id() {
        let (alice, bob) = (1, 2);
        let mut a = stores_for(alice);
        let mut b = stores_for(bob);
        let first = ready(create_distribution_message(&mut a, alice, 7)).unwrap();
        ready(process_distribution_message(&mut b, alice, 7, &first)).unwrap();
        let read = ready(encrypt_group_message(&mut a, alice, 7, b"read")).unwrap();
        let unread = ready(encrypt_group_message(&mut a, alice, 7, b"unread")).unwrap();
        ready(decrypt_group_message(&mut b, alice, 7, &read)).unwrap();
        ready(process_distribution_message(&mut b, 11, 7, &first)).unwrap();
        assert!(
            is_duplicate(ready(decrypt_group_message(&mut b, 11, 7, &read))),
            "a post read once opened again under another id"
        );
        assert_eq!(
            ready(decrypt_group_message(&mut b, 11, 7, &unread)).unwrap(),
            b"unread"
        );
    }

    /// What one connection read goes over to the next (`KeptSessions`): a key from before,
    /// handed to the new stores, opens nothing read then, and what was not read still opens.
    #[test]
    fn what_was_read_goes_over_to_the_next_stores() {
        let (alice, bob) = (1, 2);
        let mut a = stores_for(alice);
        let mut b = stores_for(bob);
        let first = ready(create_distribution_message(&mut a, alice, 7)).unwrap();
        ready(process_distribution_message(&mut b, alice, 7, &first)).unwrap();
        let read = ready(encrypt_group_message(&mut a, alice, 7, b"read")).unwrap();
        let unread = ready(encrypt_group_message(&mut a, alice, 7, b"unread")).unwrap();
        ready(decrypt_group_message(&mut b, alice, 7, &read)).unwrap();
        let mut again = stores_for(bob);
        again.sender_key.adopt_reads(b.sender_key.kept_reads());
        ready(process_distribution_message(&mut again, alice, 7, &first)).unwrap();
        assert!(
            is_duplicate(ready(decrypt_group_message(&mut again, alice, 7, &read))),
            "a post read on the last connection opened again"
        );
        assert_eq!(
            ready(decrypt_group_message(&mut again, alice, 7, &unread)).unwrap(),
            b"unread"
        );
    }

    /// A writer's record, its chain signing with another key pair: as a new chain that drew
    /// the id of an old one would (31 random bits, libsignal's `chain_id`).
    fn under_another_signing_key(record: &[u8], public: &[u8]) -> Vec<u8> {
        let pair = libsignal_protocol::KeyPair::generate(&mut crate::rng());
        let at = record
            .windows(public.len())
            .position(|w| w == public)
            .expect("the record holds its public key");
        let mut out = record.to_vec();
        out[at..at + public.len()].copy_from_slice(&pair.public_key.serialize());
        // storage.proto `SenderSigningKey`: the private half follows, field 2, 32 bytes
        let private = at + public.len();
        assert_eq!(out[private..private + 2], [0x12, 0x20]);
        out[private + 2..private + 34].copy_from_slice(&pair.private_key.serialize());
        out
    }

    /// Two chains under one chain id are two chains: a post at a position read on the first
    /// opens on the second, which signs with another key.
    #[test]
    fn a_new_chain_under_an_old_chain_id_is_not_taken_as_read() {
        let (alice, bob) = (1, 2);
        let mut a = stores_for(alice);
        let mut b = stores_for(bob);
        let first = ready(create_distribution_message(&mut a, alice, 7)).unwrap();
        let key = sender_key_key_of(alice, 7);
        let record = a.sender_key.keys[&key].clone();
        ready(process_distribution_message(&mut b, alice, 7, &first)).unwrap();
        let read = ready(encrypt_group_message(&mut a, alice, 7, b"read")).unwrap();
        ready(decrypt_group_message(&mut b, alice, 7, &read)).unwrap();
        // The same chain id and chain key from the start, under a new signing key
        let public = SenderKeyDistributionMessage::try_from(&first[..])
            .unwrap()
            .signing_key()
            .unwrap()
            .serialize();
        let mut restarted = stores_for(alice);
        restarted
            .sender_key
            .keys
            .insert(key, under_another_signing_key(&record, &public));
        let again = ready(create_distribution_message(&mut restarted, alice, 7)).unwrap();
        let (one, two) = (
            SenderKeyDistributionMessage::try_from(&first[..]).unwrap(),
            SenderKeyDistributionMessage::try_from(&again[..]).unwrap(),
        );
        assert_eq!(one.chain_id().unwrap(), two.chain_id().unwrap());
        assert_ne!(one.signing_key().unwrap(), two.signing_key().unwrap());
        ready(process_distribution_message(&mut b, alice, 7, &again)).unwrap();
        let other = ready(encrypt_group_message(&mut restarted, alice, 7, b"other")).unwrap();
        assert_eq!(
            SenderKeyMessage::try_from(&other[..]).unwrap().iteration(),
            SenderKeyMessage::try_from(&read[..]).unwrap().iteration()
        );
        let opened = ready(decrypt_group_message(&mut b, alice, 7, &other));
        assert!(
            opened.as_ref().is_ok_and(|p| p == b"other"),
            "a post on another chain was taken as read: {opened:?}"
        );
    }

    fn sender_key_key_of(user: u32, channel: u32) -> String {
        let a = user_address(user);
        format!(
            "{}.{}::{}",
            a.name(),
            a.device_id(),
            channel_distribution_id(channel)
        )
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
