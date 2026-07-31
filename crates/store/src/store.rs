use crate::backend::Backend;
use crate::seal::RecordCipher;
use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Namespace {
    Identity,

    Session,

    SenderKeySelf,

    SenderKeyPeer,

    PreKey,

    SignedPreKey,

    KtPin,

    InboundCache,

    Outbox,

    Meta,

    /// Decrypted message history, kept locally so conversations survive leaving
    /// a screen and so the server never holds plaintext.
    Message,
}

impl Namespace {
    pub fn label(self) -> &'static str {
        match self {
            Namespace::Identity => "identity",
            Namespace::Session => "session",
            Namespace::SenderKeySelf => "sender_key_self",
            Namespace::SenderKeyPeer => "sender_key_peer",
            Namespace::PreKey => "prekey",
            Namespace::SignedPreKey => "signed_prekey",
            Namespace::KtPin => "kt_pin",
            Namespace::InboundCache => "inbound_cache",
            Namespace::Outbox => "outbox",
            Namespace::Meta => "meta",
            Namespace::Message => "message",
        }
    }
}

pub struct SecureStore<B: Backend> {
    cipher: RecordCipher,
    backend: B,
}

impl<B: Backend> SecureStore<B> {
    pub fn open(master_key: &[u8], backend: B) -> Result<Self> {
        Ok(SecureStore {
            cipher: RecordCipher::new(master_key)?,
            backend,
        })
    }

    pub fn put(&mut self, namespace: Namespace, key: &[u8], value: &[u8]) -> Result<()> {
        let sealed = self.cipher.seal(namespace.label().as_bytes(), key, value);
        self.backend.put(namespace.label(), key, &sealed)
    }

    pub fn get(&self, namespace: Namespace, key: &[u8]) -> Result<Option<Vec<u8>>> {
        match self.backend.get(namespace.label(), key)? {
            None => Ok(None),
            Some(sealed) => Ok(Some(self.cipher.open(
                namespace.label().as_bytes(),
                key,
                &sealed,
            )?)),
        }
    }

    pub fn delete(&mut self, namespace: Namespace, key: &[u8]) -> Result<()> {
        self.backend.delete(namespace.label(), key)
    }

    pub fn list(&self, namespace: Namespace) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut out = Vec::new();
        for (key, sealed) in self.backend.list(namespace.label())? {
            let value = self
                .cipher
                .open(namespace.label().as_bytes(), &key, &sealed)?;
            out.push((key, value));
        }
        Ok(out)
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn into_backend(self) -> B {
        self.backend
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MemoryBackend;
    use crate::seal::MASTER_KEY_LEN;

    fn store() -> SecureStore<MemoryBackend> {
        SecureStore::open(&[3u8; MASTER_KEY_LEN], MemoryBackend::new()).unwrap()
    }

    #[test]
    fn put_get_delete_roundtrip() {
        let mut s = store();
        s.put(Namespace::Session, b"peer-1", b"ratchet-a").unwrap();
        assert_eq!(
            s.get(Namespace::Session, b"peer-1").unwrap().as_deref(),
            Some(b"ratchet-a".as_ref())
        );
        s.put(Namespace::Session, b"peer-1", b"ratchet-b").unwrap();
        assert_eq!(
            s.get(Namespace::Session, b"peer-1").unwrap().as_deref(),
            Some(b"ratchet-b".as_ref())
        );
        s.delete(Namespace::Session, b"peer-1").unwrap();
        assert_eq!(s.get(Namespace::Session, b"peer-1").unwrap(), None);
    }

    #[test]
    fn namespaces_are_isolated() {
        let mut s = store();
        s.put(Namespace::Session, b"k", b"session-value").unwrap();
        s.put(Namespace::PreKey, b"k", b"prekey-value").unwrap();
        assert_eq!(
            s.get(Namespace::Session, b"k").unwrap().as_deref(),
            Some(b"session-value".as_ref())
        );
        assert_eq!(
            s.get(Namespace::PreKey, b"k").unwrap().as_deref(),
            Some(b"prekey-value".as_ref())
        );
    }

    #[test]
    fn backend_holds_only_ciphertext() {
        let mut s = store();
        s.put(Namespace::Session, b"peer-1", b"super-secret-plaintext")
            .unwrap();
        let raw = s
            .backend()
            .get(Namespace::Session.label(), b"peer-1")
            .unwrap()
            .unwrap();
        assert!(
            !raw.windows(b"super-secret-plaintext".len())
                .any(|w| w == b"super-secret-plaintext"),
            "plaintext must never appear in the backend"
        );
    }

    #[test]
    fn list_returns_sorted_opened_records() {
        let mut s = store();
        s.put(Namespace::Outbox, b"b", b"2").unwrap();
        s.put(Namespace::Outbox, b"a", b"1").unwrap();
        s.put(Namespace::Outbox, b"c", b"3").unwrap();
        let items = s.list(Namespace::Outbox).unwrap();
        assert_eq!(
            items,
            vec![
                (b"a".to_vec(), b"1".to_vec()),
                (b"b".to_vec(), b"2".to_vec()),
                (b"c".to_vec(), b"3".to_vec()),
            ]
        );
    }
}
