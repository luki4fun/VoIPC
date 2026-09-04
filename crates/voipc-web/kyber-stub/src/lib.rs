//! Stub standing in for `pqcrypto-kyber` in the wasm build. The real crate
//! wraps PQClean C code that does not compile for wasm32-unknown-unknown.
//!
//! VoIPC never negotiates Kyber: pre-key bundles carry no Kyber keys
//! (`voipc_crypto::session::establish_session`) and the `KyberPreKeyStore`
//! in `voipc_crypto::stores` is a no-op, so libsignal only needs these
//! symbols to link. Every function panics if it is ever reached.

/// Size constants libsignal reads for its KEM parameter types.
pub mod ffi {
    pub const PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 2400;
    pub const PQCLEAN_KYBER768_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 1184;
    pub const PQCLEAN_KYBER768_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 1088;
    pub const PQCLEAN_KYBER768_CLEAN_CRYPTO_BYTES: usize = 32;
    pub const PQCLEAN_KYBER1024_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 3168;
    pub const PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 1568;
    pub const PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 1568;
    pub const PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES: usize = 32;
}

const UNSUPPORTED: &str = "kyber unsupported in web build";

/// One KEM value type implementing the matching `pqcrypto_traits::kem` trait.
macro_rules! stub_type {
    ($ty:ident) => {
        #[derive(Clone, Copy)]
        pub struct $ty;

        impl pqcrypto_traits::kem::$ty for $ty {
            fn as_bytes(&self) -> &[u8] {
                unreachable!("{}", crate::UNSUPPORTED)
            }

            fn from_bytes(_: &[u8]) -> pqcrypto_traits::Result<Self> {
                unreachable!("{}", crate::UNSUPPORTED)
            }
        }
    };
}

/// One parameter set module with the API surface libsignal's kem module uses.
macro_rules! stub_kem {
    ($name:ident) => {
        pub mod $name {
            stub_type!(PublicKey);
            stub_type!(SecretKey);
            stub_type!(Ciphertext);
            stub_type!(SharedSecret);

            pub fn keypair() -> (PublicKey, SecretKey) {
                unreachable!("{}", crate::UNSUPPORTED)
            }

            pub fn encapsulate(_: &PublicKey) -> (SharedSecret, Ciphertext) {
                unreachable!("{}", crate::UNSUPPORTED)
            }

            pub fn decapsulate(_: &Ciphertext, _: &SecretKey) -> SharedSecret {
                unreachable!("{}", crate::UNSUPPORTED)
            }
        }
    };
}

stub_kem!(kyber768);
stub_kem!(kyber1024);
