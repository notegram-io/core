use rand_core::OsRng;
use ratchet::DoubleRatchet;
use store::{Backend, Namespace, SecureStore};

use crate::identity::{Identity, PublicIdentity};
use crate::session::{
    establish_inbound, establish_outbound, InboundPreKeys, PeerAddress, PreKeyBundle,
};
use crate::{Result, SdkError};

const IDENTITY_KEY: &[u8] = b"self";

pub struct NotegramClient<B: Backend> {
    store: SecureStore<B>,
}

impl<B: Backend> NotegramClient<B> {
    pub fn open(master_key: &[u8], backend: B) -> Result<Self> {
        Ok(NotegramClient {
            store: SecureStore::open(master_key, backend)?,
        })
    }

    pub fn create_identity(&mut self) -> Result<PublicIdentity> {
        let identity = Identity::generate(&mut OsRng);
        self.store
            .put(Namespace::Identity, IDENTITY_KEY, &identity.serialize())?;
        Ok(identity.public())
    }

    pub fn import_identity(&mut self, identity: &Identity) -> Result<PublicIdentity> {
        self.store
            .put(Namespace::Identity, IDENTITY_KEY, &identity.serialize())?;
        Ok(identity.public())
    }

    pub fn public_identity(&self) -> Result<PublicIdentity> {
        Ok(self.load_identity()?.public())
    }

    pub fn into_backend(self) -> B {
        self.store.into_backend()
    }

    pub fn has_session(&self, peer: PeerAddress) -> Result<bool> {
        Ok(self
            .store
            .get(Namespace::Session, &peer.store_key())?
            .is_some())
    }

    pub fn establish_outbound_session(
        &mut self,
        peer: PeerAddress,
        bundle: &PreKeyBundle,
    ) -> Result<[u8; 32]> {
        let identity = self.load_identity()?;
        let session = establish_outbound(&identity, bundle, &mut OsRng)?;
        self.save_session(peer, &session.ratchet)?;
        Ok(session.ephemeral_pub)
    }

    pub fn establish_inbound_session(
        &mut self,
        peer: PeerAddress,
        prekeys: &InboundPreKeys,
        initiator_identity_pub: &[u8; 32],
        initiator_ephemeral_pub: &[u8; 32],
    ) -> Result<()> {
        let identity = self.load_identity()?;
        let ratchet = establish_inbound(
            &identity,
            prekeys,
            initiator_identity_pub,
            initiator_ephemeral_pub,
        );
        self.save_session(peer, &ratchet)
    }

    pub fn encrypt(
        &mut self,
        peer: PeerAddress,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        let mut ratchet = self.load_session(peer)?;
        let ciphertext = ratchet.encrypt(plaintext, associated_data)?;
        self.save_session(peer, &ratchet)?;
        Ok(ciphertext)
    }

    pub fn decrypt(
        &mut self,
        peer: PeerAddress,
        message: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        let mut ratchet = self.load_session(peer)?;
        let plaintext = ratchet.decrypt(message, associated_data, &mut OsRng)?;
        self.save_session(peer, &ratchet)?;
        Ok(plaintext)
    }

    fn load_identity(&self) -> Result<Identity> {
        match self.store.get(Namespace::Identity, IDENTITY_KEY)? {
            None => Err(SdkError::NoIdentity),
            Some(bytes) => Identity::deserialize(&bytes),
        }
    }

    fn load_session(&self, peer: PeerAddress) -> Result<DoubleRatchet> {
        match self.store.get(Namespace::Session, &peer.store_key())? {
            None => Err(SdkError::NoSession),
            Some(bytes) => Ok(DoubleRatchet::deserialize(&bytes)?),
        }
    }

    fn save_session(&mut self, peer: PeerAddress, ratchet: &DoubleRatchet) -> Result<()> {
        self.store
            .put(Namespace::Session, &peer.store_key(), &ratchet.serialize())?;
        Ok(())
    }
}
