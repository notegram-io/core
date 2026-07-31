//! Generated TL message types. DO NOT EDIT — regenerate with
//! `go run ./tl/cmd/gen -in tl/schema/schema.tl -lang rust ...` from commons.
#![allow(dead_code)]

use crate::{Decoder, Encoder, Result, TlObject};

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuthActionResult {
    pub device_id: i64,
    pub revoked_sessions: i32,
    pub disabled: bool,
}

impl TlObject for AuthActionResult {
    const CTOR: u32 = 0xe6ac8431;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.device_id);
        e.int(self.revoked_sessions);
        e.bool(self.disabled);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let device_id = d.long()?;
        let revoked_sessions = d.int()?;
        let disabled = d.bool()?;
        d.leave();
        Ok(Self {
            device_id,
            revoked_sessions,
            disabled,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuthBeginHandshake {
    pub tmp_token: Vec<u8>,
    pub client_nonce: Vec<u8>,
    pub client_eph_pub: Vec<u8>,
    pub client_info: Vec<u8>,
}

impl TlObject for AuthBeginHandshake {
    const CTOR: u32 = 0xa8f3d9c1;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.bytes(&self.tmp_token)?;
        e.bytes(&self.client_nonce)?;
        e.bytes(&self.client_eph_pub)?;
        e.bytes(&self.client_info)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let tmp_token = d.bytes()?;
        let client_nonce = d.bytes()?;
        let client_eph_pub = d.bytes()?;
        let client_info = d.bytes()?;
        d.leave();
        Ok(Self {
            tmp_token,
            client_nonce,
            client_eph_pub,
            client_info,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuthCreateDeviceLink;

impl TlObject for AuthCreateDeviceLink {
    const CTOR: u32 = 0x5f0c1e72;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        d.leave();
        Ok(Self)
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuthDevice {
    pub device_id: i64,
    pub purpose: String,
    pub created_at: i64,
    pub last_authenticated_at: i64,
    pub last_session_id: u64,
    pub last_auth_key_id: u64,
    pub disabled: bool,
    pub disabled_at: Option<i64>,
    pub linked_by_device_id: Option<i64>,
    pub bootstrap_ready_at: Option<i64>,
    pub bootstrap_completed_at: Option<i64>,
    pub bootstrap_source_device_id: Option<i64>,
    pub bootstrap_required: bool,
    pub current: bool,
}

impl TlObject for AuthDevice {
    const CTOR: u32 = 0xa3c992e4;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        let mut flags = crate::Flags(0);
        flags = flags.set(0, self.disabled_at.is_some());
        flags = flags.set(1, self.linked_by_device_id.is_some());
        flags = flags.set(2, self.bootstrap_ready_at.is_some());
        flags = flags.set(3, self.bootstrap_completed_at.is_some());
        flags = flags.set(4, self.bootstrap_source_device_id.is_some());
        e.uint(flags.0);
        e.long(self.device_id);
        e.string(&self.purpose)?;
        e.long(self.created_at);
        e.long(self.last_authenticated_at);
        e.ulong(self.last_session_id);
        e.ulong(self.last_auth_key_id);
        e.bool(self.disabled);
        if let Some(__v) = &self.disabled_at {
            e.long(*__v);
        }
        if let Some(__v) = &self.linked_by_device_id {
            e.long(*__v);
        }
        if let Some(__v) = &self.bootstrap_ready_at {
            e.long(*__v);
        }
        if let Some(__v) = &self.bootstrap_completed_at {
            e.long(*__v);
        }
        if let Some(__v) = &self.bootstrap_source_device_id {
            e.long(*__v);
        }
        e.bool(self.bootstrap_required);
        e.bool(self.current);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let flags = crate::Flags(d.uint()?);
        let device_id = d.long()?;
        let purpose = d.string()?;
        let created_at = d.long()?;
        let last_authenticated_at = d.long()?;
        let last_session_id = d.ulong()?;
        let last_auth_key_id = d.ulong()?;
        let disabled = d.bool()?;
        let disabled_at = if flags.has(0) { Some(d.long()?) } else { None };
        let linked_by_device_id = if flags.has(1) { Some(d.long()?) } else { None };
        let bootstrap_ready_at = if flags.has(2) { Some(d.long()?) } else { None };
        let bootstrap_completed_at = if flags.has(3) { Some(d.long()?) } else { None };
        let bootstrap_source_device_id = if flags.has(4) { Some(d.long()?) } else { None };
        let bootstrap_required = d.bool()?;
        let current = d.bool()?;
        d.leave();
        Ok(Self {
            device_id,
            purpose,
            created_at,
            last_authenticated_at,
            last_session_id,
            last_auth_key_id,
            disabled,
            disabled_at,
            linked_by_device_id,
            bootstrap_ready_at,
            bootstrap_completed_at,
            bootstrap_source_device_id,
            bootstrap_required,
            current,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuthDeviceLinkToken {
    pub link_token: Vec<u8>,
    pub issued_by_device_id: i64,
    pub expires_in: i32,
    pub link_fingerprint: Vec<u8>,
    pub verification_phrase: String,
    pub qr_payload: String,
}

impl TlObject for AuthDeviceLinkToken {
    const CTOR: u32 = 0x8b2d7a34;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.bytes(&self.link_token)?;
        e.long(self.issued_by_device_id);
        e.int(self.expires_in);
        e.bytes(&self.link_fingerprint)?;
        e.string(&self.verification_phrase)?;
        e.string(&self.qr_payload)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let link_token = d.bytes()?;
        let issued_by_device_id = d.long()?;
        let expires_in = d.int()?;
        let link_fingerprint = d.bytes()?;
        let verification_phrase = d.string()?;
        let qr_payload = d.string()?;
        d.leave();
        Ok(Self {
            link_token,
            issued_by_device_id,
            expires_in,
            link_fingerprint,
            verification_phrase,
            qr_payload,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuthDevices {
    pub devices: Vec<AuthDevice>,
}

impl TlObject for AuthDevices {
    const CTOR: u32 = 0x7b14f82a;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        {
            let __v = &self.devices;
            e.vector_header(__v.len())?;
            for __x in __v {
                __x.encode(e)?;
            }
        }
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let devices = {
            let __n = d.vector_header()?;
            let mut __v = Vec::with_capacity(__n);
            for _ in 0..__n {
                __v.push(AuthDevice::decode(d)?);
            }
            __v
        };
        d.leave();
        Ok(Self {
            devices,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuthDisableDevice {
    pub device_id: i64,
}

impl TlObject for AuthDisableDevice {
    const CTOR: u32 = 0xf3ac01de;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.device_id);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let device_id = d.long()?;
        d.leave();
        Ok(Self {
            device_id,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuthFinishHandshake {
    pub tmp_token: Vec<u8>,
    pub client_nonce: Vec<u8>,
    pub server_nonce: Vec<u8>,
    pub epoch: i32,
    pub client_finished: Vec<u8>,
}

impl TlObject for AuthFinishHandshake {
    const CTOR: u32 = 0xc3f5a2ee;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.bytes(&self.tmp_token)?;
        e.bytes(&self.client_nonce)?;
        e.bytes(&self.server_nonce)?;
        e.int(self.epoch);
        e.bytes(&self.client_finished)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let tmp_token = d.bytes()?;
        let client_nonce = d.bytes()?;
        let server_nonce = d.bytes()?;
        let epoch = d.int()?;
        let client_finished = d.bytes()?;
        d.leave();
        Ok(Self {
            tmp_token,
            client_nonce,
            server_nonce,
            epoch,
            client_finished,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuthGetDevices;

impl TlObject for AuthGetDevices {
    const CTOR: u32 = 0x50fbf6d1;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        d.leave();
        Ok(Self)
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuthHandshakeOk {
    pub auth_key_id: u64,
    pub epoch: i32,
    pub server_finished: Vec<u8>,
    pub expires_in: i32,
}

impl TlObject for AuthHandshakeOk {
    const CTOR: u32 = 0xd0e7a91d;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.ulong(self.auth_key_id);
        e.int(self.epoch);
        e.bytes(&self.server_finished)?;
        e.int(self.expires_in);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let auth_key_id = d.ulong()?;
        let epoch = d.int()?;
        let server_finished = d.bytes()?;
        let expires_in = d.int()?;
        d.leave();
        Ok(Self {
            auth_key_id,
            epoch,
            server_finished,
            expires_in,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuthHandshakeParams {
    pub server_nonce: Vec<u8>,
    pub server_eph_pub: Vec<u8>,
    pub server_pub_key_id: i64,
    pub sig: Vec<u8>,
    pub salt: u64,
    pub epoch: i32,
    pub expires_in: i32,
}

impl TlObject for AuthHandshakeParams {
    const CTOR: u32 = 0xb7a2c4e6;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.bytes(&self.server_nonce)?;
        e.bytes(&self.server_eph_pub)?;
        e.long(self.server_pub_key_id);
        e.bytes(&self.sig)?;
        e.ulong(self.salt);
        e.int(self.epoch);
        e.int(self.expires_in);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let server_nonce = d.bytes()?;
        let server_eph_pub = d.bytes()?;
        let server_pub_key_id = d.long()?;
        let sig = d.bytes()?;
        let salt = d.ulong()?;
        let epoch = d.int()?;
        let expires_in = d.int()?;
        d.leave();
        Ok(Self {
            server_nonce,
            server_eph_pub,
            server_pub_key_id,
            sig,
            salt,
            epoch,
            expires_in,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuthLogoutCurrent;

impl TlObject for AuthLogoutCurrent {
    const CTOR: u32 = 0x5169b8c3;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        d.leave();
        Ok(Self)
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuthLogoutDevice {
    pub device_id: i64,
}

impl TlObject for AuthLogoutDevice {
    const CTOR: u32 = 0xc8925a71;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.device_id);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let device_id = d.long()?;
        d.leave();
        Ok(Self {
            device_id,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuthRedeemDeviceLink {
    pub link_token: Vec<u8>,
    pub device_id: i64,
    pub link_fingerprint: Vec<u8>,
    pub verification_phrase: String,
}

impl TlObject for AuthRedeemDeviceLink {
    const CTOR: u32 = 0x92a61d48;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.bytes(&self.link_token)?;
        e.long(self.device_id);
        e.bytes(&self.link_fingerprint)?;
        e.string(&self.verification_phrase)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let link_token = d.bytes()?;
        let device_id = d.long()?;
        let link_fingerprint = d.bytes()?;
        let verification_phrase = d.string()?;
        d.leave();
        Ok(Self {
            link_token,
            device_id,
            link_fingerprint,
            verification_phrase,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuthSendEmailCode {
    pub email: String,
    pub purpose: String,
    pub device_id: i64,
}

impl TlObject for AuthSendEmailCode {
    const CTOR: u32 = 0x7e0bf3ed;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.string(&self.email)?;
        e.string(&self.purpose)?;
        e.long(self.device_id);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let email = d.string()?;
        let purpose = d.string()?;
        let device_id = d.long()?;
        d.leave();
        Ok(Self {
            email,
            purpose,
            device_id,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuthSentCode {
    pub email: String,
    pub email_hash: Vec<u8>,
    pub timeout: i32,
}

impl TlObject for AuthSentCode {
    const CTOR: u32 = 0x80d2a736;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.string(&self.email)?;
        e.bytes(&self.email_hash)?;
        e.int(self.timeout);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let email = d.string()?;
        let email_hash = d.bytes()?;
        let timeout = d.int()?;
        d.leave();
        Ok(Self {
            email,
            email_hash,
            timeout,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuthVerified {
    pub user_id: i64,
    pub tmp_token: Vec<u8>,
    pub expires_in: i32,
}

impl TlObject for AuthVerified {
    const CTOR: u32 = 0x2f84b3b1;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.user_id);
        e.bytes(&self.tmp_token)?;
        e.int(self.expires_in);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let user_id = d.long()?;
        let tmp_token = d.bytes()?;
        let expires_in = d.int()?;
        d.leave();
        Ok(Self {
            user_id,
            tmp_token,
            expires_in,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuthVerifyEmailCode {
    pub email: String,
    pub email_hash: Vec<u8>,
    pub code: String,
}

impl TlObject for AuthVerifyEmailCode {
    const CTOR: u32 = 0xdfbe3f0f;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.string(&self.email)?;
        e.bytes(&self.email_hash)?;
        e.string(&self.code)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let email = d.string()?;
        let email_hash = d.bytes()?;
        let code = d.string()?;
        d.leave();
        Ok(Self {
            email,
            email_hash,
            code,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DcOption {
    pub id: i32,
    pub host: String,
    pub port: i32,
}

impl TlObject for DcOption {
    const CTOR: u32 = 0xa2f97626;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.int(self.id);
        e.string(&self.host)?;
        e.int(self.port);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let id = d.int()?;
        let host = d.string()?;
        let port = d.int()?;
        d.leave();
        Ok(Self {
            id,
            host,
            port,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DevicePrekeyBundle {
    pub device_id: i64,
    pub identity_key: Vec<u8>,
    pub signed_pre_key_id: i32,
    pub signed_pre_key_pub: Vec<u8>,
    pub signed_pre_key_sig: Vec<u8>,
    pub one_time_pre_key_id: i32,
    pub one_time_pre_key_pub: Vec<u8>,
    pub updated_at: i64,
    pub proof: Vec<u8>,
}

impl TlObject for DevicePrekeyBundle {
    const CTOR: u32 = 0x78ab31c4;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.device_id);
        e.bytes(&self.identity_key)?;
        e.int(self.signed_pre_key_id);
        e.bytes(&self.signed_pre_key_pub)?;
        e.bytes(&self.signed_pre_key_sig)?;
        e.int(self.one_time_pre_key_id);
        e.bytes(&self.one_time_pre_key_pub)?;
        e.long(self.updated_at);
        e.bytes(&self.proof)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let device_id = d.long()?;
        let identity_key = d.bytes()?;
        let signed_pre_key_id = d.int()?;
        let signed_pre_key_pub = d.bytes()?;
        let signed_pre_key_sig = d.bytes()?;
        let one_time_pre_key_id = d.int()?;
        let one_time_pre_key_pub = d.bytes()?;
        let updated_at = d.long()?;
        let proof = d.bytes()?;
        d.leave();
        Ok(Self {
            device_id,
            identity_key,
            signed_pre_key_id,
            signed_pre_key_pub,
            signed_pre_key_sig,
            one_time_pre_key_id,
            one_time_pre_key_pub,
            updated_at,
            proof,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DirectoryChangeUsername {
    pub name: String,
}

impl TlObject for DirectoryChangeUsername {
    const CTOR: u32 = 0xd1a10002;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.string(&self.name)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let name = d.string()?;
        d.leave();
        Ok(Self {
            name,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DirectoryClaimUsername {
    pub name: String,
}

impl TlObject for DirectoryClaimUsername {
    const CTOR: u32 = 0xd1a10001;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.string(&self.name)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let name = d.string()?;
        d.leave();
        Ok(Self {
            name,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DirectoryDiscovery {
    pub user_id: i64,
    pub discoverable_by_username: bool,
    pub updated_at: i64,
}

impl TlObject for DirectoryDiscovery {
    const CTOR: u32 = 0xd1a1000d;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.user_id);
        e.bool(self.discoverable_by_username);
        e.long(self.updated_at);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let user_id = d.long()?;
        let discoverable_by_username = d.bool()?;
        let updated_at = d.long()?;
        d.leave();
        Ok(Self {
            user_id,
            discoverable_by_username,
            updated_at,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DirectoryGetMyProfile;

impl TlObject for DirectoryGetMyProfile {
    const CTOR: u32 = 0xd1a10008;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        d.leave();
        Ok(Self)
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DirectoryGetMyUsername;

impl TlObject for DirectoryGetMyUsername {
    const CTOR: u32 = 0xd1a10005;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        d.leave();
        Ok(Self)
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DirectoryGetProfile {
    pub user_id: i64,
}

impl TlObject for DirectoryGetProfile {
    const CTOR: u32 = 0xd1a10007;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.user_id);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let user_id = d.long()?;
        d.leave();
        Ok(Self {
            user_id,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DirectoryProfile {
    pub user_id: i64,
    pub display_name: String,
    pub bio: String,
    pub avatar_ref: String,
    pub version: i64,
    pub updated_at: i64,
}

impl TlObject for DirectoryProfile {
    const CTOR: u32 = 0xd1a1000c;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.user_id);
        e.string(&self.display_name)?;
        e.string(&self.bio)?;
        e.string(&self.avatar_ref)?;
        e.long(self.version);
        e.long(self.updated_at);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let user_id = d.long()?;
        let display_name = d.string()?;
        let bio = d.string()?;
        let avatar_ref = d.string()?;
        let version = d.long()?;
        let updated_at = d.long()?;
        d.leave();
        Ok(Self {
            user_id,
            display_name,
            bio,
            avatar_ref,
            version,
            updated_at,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DirectoryReleaseUsername;

impl TlObject for DirectoryReleaseUsername {
    const CTOR: u32 = 0xd1a10003;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        d.leave();
        Ok(Self)
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DirectoryResolveUsername {
    pub name: String,
}

impl TlObject for DirectoryResolveUsername {
    const CTOR: u32 = 0xd1a10004;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.string(&self.name)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let name = d.string()?;
        d.leave();
        Ok(Self {
            name,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DirectoryResolved {
    pub username: String,
    pub user_id: i64,
    pub display_name: String,
    pub proof: Vec<u8>,
}

impl TlObject for DirectoryResolved {
    const CTOR: u32 = 0xd1a1000b;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.string(&self.username)?;
        e.long(self.user_id);
        e.string(&self.display_name)?;
        e.bytes(&self.proof)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let username = d.string()?;
        let user_id = d.long()?;
        let display_name = d.string()?;
        let proof = d.bytes()?;
        d.leave();
        Ok(Self {
            username,
            user_id,
            display_name,
            proof,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DirectorySetDiscovery {
    pub discoverable_by_username: bool,
}

impl TlObject for DirectorySetDiscovery {
    const CTOR: u32 = 0xd1a10009;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.bool(self.discoverable_by_username);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let discoverable_by_username = d.bool()?;
        d.leave();
        Ok(Self {
            discoverable_by_username,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DirectorySetProfile {
    pub display_name: String,
    pub bio: String,
}

impl TlObject for DirectorySetProfile {
    const CTOR: u32 = 0xd1a10006;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.string(&self.display_name)?;
        e.string(&self.bio)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let display_name = d.string()?;
        let bio = d.string()?;
        d.leave();
        Ok(Self {
            display_name,
            bio,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DirectoryUsername {
    pub username: String,
    pub user_id: i64,
    pub allocation_type: String,
    pub owner_ref: String,
    pub created_at: i64,
    pub updated_at: i64,
}

impl TlObject for DirectoryUsername {
    const CTOR: u32 = 0xd1a1000a;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.string(&self.username)?;
        e.long(self.user_id);
        e.string(&self.allocation_type)?;
        e.string(&self.owner_ref)?;
        e.long(self.created_at);
        e.long(self.updated_at);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let username = d.string()?;
        let user_id = d.long()?;
        let allocation_type = d.string()?;
        let owner_ref = d.string()?;
        let created_at = d.long()?;
        let updated_at = d.long()?;
        d.leave();
        Ok(Self {
            username,
            user_id,
            allocation_type,
            owner_ref,
            created_at,
            updated_at,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct FloodWait {
    pub wait: i32,
    pub message: String,
}

impl TlObject for FloodWait {
    const CTOR: u32 = 0xd6d2c5b4;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.int(self.wait);
        e.string(&self.message)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let wait = d.int()?;
        let message = d.string()?;
        d.leave();
        Ok(Self {
            wait,
            message,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct HelpConfig {
    pub now: i32,
    pub dc_options: Vec<DcOption>,
}

impl TlObject for HelpConfig {
    const CTOR: u32 = 0xeeef14b2;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.int(self.now);
        {
            let __v = &self.dc_options;
            e.vector_header(__v.len())?;
            for __x in __v {
                __x.encode(e)?;
            }
        }
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let now = d.int()?;
        let dc_options = {
            let __n = d.vector_header()?;
            let mut __v = Vec::with_capacity(__n);
            for _ in 0..__n {
                __v.push(DcOption::decode(d)?);
            }
            __v
        };
        d.leave();
        Ok(Self {
            now,
            dc_options,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct HelpGetConfig;

impl TlObject for HelpGetConfig {
    const CTOR: u32 = 0xcbc9a04d;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        d.leave();
        Ok(Self)
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct IdentityDeviceState {
    pub device_id: i64,
    pub identity_key: Vec<u8>,
    pub identity_created_at: i64,
    pub signed_pre_key_id: i32,
    pub signed_pre_key_updated_at: i64,
    pub updated_at: i64,
}

impl TlObject for IdentityDeviceState {
    const CTOR: u32 = 0x51e8db02;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.device_id);
        e.bytes(&self.identity_key)?;
        e.long(self.identity_created_at);
        e.int(self.signed_pre_key_id);
        e.long(self.signed_pre_key_updated_at);
        e.long(self.updated_at);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let device_id = d.long()?;
        let identity_key = d.bytes()?;
        let identity_created_at = d.long()?;
        let signed_pre_key_id = d.int()?;
        let signed_pre_key_updated_at = d.long()?;
        let updated_at = d.long()?;
        d.leave();
        Ok(Self {
            device_id,
            identity_key,
            identity_created_at,
            signed_pre_key_id,
            signed_pre_key_updated_at,
            updated_at,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct InvokeWithLayer {
    pub layer: i32,
    pub query: Vec<u8>,
}

impl TlObject for InvokeWithLayer {
    const CTOR: u32 = 0x4594c318;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.int(self.layer);
        e.bytes(&self.query)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let layer = d.int()?;
        let query = d.bytes()?;
        d.leave();
        Ok(Self {
            layer,
            query,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysAckArtifact {
    pub artifact_id: String,
    pub bootstrap_proof: Option<Vec<u8>>,
    pub bootstrap_signing_key: Option<Vec<u8>>,
    pub bootstrap_admission_signature: Option<Vec<u8>>,
    pub session_sync_ack_proof: Option<Vec<u8>>,
}

impl TlObject for KeysAckArtifact {
    const CTOR: u32 = 0x6d3baf11;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        let mut flags = crate::Flags(0);
        flags = flags.set(0, self.bootstrap_proof.is_some());
        flags = flags.set(1, self.bootstrap_signing_key.is_some());
        flags = flags.set(2, self.bootstrap_admission_signature.is_some());
        flags = flags.set(3, self.session_sync_ack_proof.is_some());
        e.uint(flags.0);
        e.string(&self.artifact_id)?;
        if let Some(__v) = &self.bootstrap_proof {
            e.bytes(__v)?;
        }
        if let Some(__v) = &self.bootstrap_signing_key {
            e.bytes(__v)?;
        }
        if let Some(__v) = &self.bootstrap_admission_signature {
            e.bytes(__v)?;
        }
        if let Some(__v) = &self.session_sync_ack_proof {
            e.bytes(__v)?;
        }
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let flags = crate::Flags(d.uint()?);
        let artifact_id = d.string()?;
        let bootstrap_proof = if flags.has(0) { Some(d.bytes()?) } else { None };
        let bootstrap_signing_key = if flags.has(1) { Some(d.bytes()?) } else { None };
        let bootstrap_admission_signature = if flags.has(2) { Some(d.bytes()?) } else { None };
        let session_sync_ack_proof = if flags.has(3) { Some(d.bytes()?) } else { None };
        d.leave();
        Ok(Self {
            artifact_id,
            bootstrap_proof,
            bootstrap_signing_key,
            bootstrap_admission_signature,
            session_sync_ack_proof,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysArtifact {
    pub artifact_id: String,
    pub owner_device_id: i64,
    pub client_ref: String,
    pub kind: String,
    pub schema: String,
    pub ciphertext: Vec<u8>,
    pub metadata: Vec<u8>,
    pub created_at: i64,
    pub expires_at: i64,
}

impl TlObject for KeysArtifact {
    const CTOR: u32 = 0x8b10d5c4;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.string(&self.artifact_id)?;
        e.long(self.owner_device_id);
        e.string(&self.client_ref)?;
        e.string(&self.kind)?;
        e.string(&self.schema)?;
        e.bytes(&self.ciphertext)?;
        e.bytes(&self.metadata)?;
        e.long(self.created_at);
        e.long(self.expires_at);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let artifact_id = d.string()?;
        let owner_device_id = d.long()?;
        let client_ref = d.string()?;
        let kind = d.string()?;
        let schema = d.string()?;
        let ciphertext = d.bytes()?;
        let metadata = d.bytes()?;
        let created_at = d.long()?;
        let expires_at = d.long()?;
        d.leave();
        Ok(Self {
            artifact_id,
            owner_device_id,
            client_ref,
            kind,
            schema,
            ciphertext,
            metadata,
            created_at,
            expires_at,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysArtifactAcked {
    pub artifact_id: String,
    pub deleted: bool,
}

impl TlObject for KeysArtifactAcked {
    const CTOR: u32 = 0x2a74c981;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.string(&self.artifact_id)?;
        e.bool(self.deleted);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let artifact_id = d.string()?;
        let deleted = d.bool()?;
        d.leave();
        Ok(Self {
            artifact_id,
            deleted,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysArtifactStored {
    pub artifact_id: String,
    pub created_at: i64,
    pub expires_at: i64,
}

impl TlObject for KeysArtifactStored {
    const CTOR: u32 = 0x0f53ac72;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.string(&self.artifact_id)?;
        e.long(self.created_at);
        e.long(self.expires_at);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let artifact_id = d.string()?;
        let created_at = d.long()?;
        let expires_at = d.long()?;
        d.leave();
        Ok(Self {
            artifact_id,
            created_at,
            expires_at,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysArtifacts {
    pub items: Vec<KeysArtifact>,
}

impl TlObject for KeysArtifacts {
    const CTOR: u32 = 0x9f2e71c0;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        {
            let __v = &self.items;
            e.vector_header(__v.len())?;
            for __x in __v {
                __x.encode(e)?;
            }
        }
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let items = {
            let __n = d.vector_header()?;
            let mut __v = Vec::with_capacity(__n);
            for _ in 0..__n {
                __v.push(KeysArtifact::decode(d)?);
            }
            __v
        };
        d.leave();
        Ok(Self {
            items,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysCapabilities {
    pub user_id: i64,
    pub device_id: i64,
    pub updated_at: i64,
    pub features: Vec<String>,
}

impl TlObject for KeysCapabilities {
    const CTOR: u32 = 0xb9d7a101;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.user_id);
        e.long(self.device_id);
        e.long(self.updated_at);
        {
            let __v = &self.features;
            e.vector_header(__v.len())?;
            for __x in __v {
                e.string(__x)?;
            }
        }
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let user_id = d.long()?;
        let device_id = d.long()?;
        let updated_at = d.long()?;
        let features = {
            let __n = d.vector_header()?;
            let mut __v = Vec::with_capacity(__n);
            for _ in 0..__n {
                __v.push(d.string()?);
            }
            __v
        };
        d.leave();
        Ok(Self {
            user_id,
            device_id,
            updated_at,
            features,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysDeviceSigningKey {
    pub device_id: i64,
    pub public_key: Vec<u8>,
    pub updated_at: i64,
}

impl TlObject for KeysDeviceSigningKey {
    const CTOR: u32 = 0x1b5bb3c8;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.device_id);
        e.bytes(&self.public_key)?;
        e.long(self.updated_at);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let device_id = d.long()?;
        let public_key = d.bytes()?;
        let updated_at = d.long()?;
        d.leave();
        Ok(Self {
            device_id,
            public_key,
            updated_at,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysGetArtifacts {
    pub limit: i32,
}

impl TlObject for KeysGetArtifacts {
    const CTOR: u32 = 0x4ec91a30;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.int(self.limit);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let limit = d.int()?;
        d.leave();
        Ok(Self {
            limit,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysGetCapabilities {
    pub user_id: i64,
    pub device_id: i64,
}

impl TlObject for KeysGetCapabilities {
    const CTOR: u32 = 0x1adcbf10;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.user_id);
        e.long(self.device_id);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let user_id = d.long()?;
        let device_id = d.long()?;
        d.leave();
        Ok(Self {
            user_id,
            device_id,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysGetIdentityPin {
    pub user_id: i64,
}

impl TlObject for KeysGetIdentityPin {
    const CTOR: u32 = 0x133f038f;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.user_id);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let user_id = d.long()?;
        d.leave();
        Ok(Self {
            user_id,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysGetMyIdentity;

impl TlObject for KeysGetMyIdentity {
    const CTOR: u32 = 0xf23dc701;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        d.leave();
        Ok(Self)
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysGetMyStatus;

impl TlObject for KeysGetMyStatus {
    const CTOR: u32 = 0x1f847e2a;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        d.leave();
        Ok(Self)
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysGetMyVerification;

impl TlObject for KeysGetMyVerification {
    const CTOR: u32 = 0x7d7af58c;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        d.leave();
        Ok(Self)
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysGetPeerBundle {
    pub user_id: i64,
}

impl TlObject for KeysGetPeerBundle {
    const CTOR: u32 = 0xa4ce29b7;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.user_id);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let user_id = d.long()?;
        d.leave();
        Ok(Self {
            user_id,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysGetPeerIdentity {
    pub user_id: i64,
}

impl TlObject for KeysGetPeerIdentity {
    const CTOR: u32 = 0xd35fef21;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.user_id);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let user_id = d.long()?;
        d.leave();
        Ok(Self {
            user_id,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysGetPeerPackages {
    pub user_id: i64,
    pub limit: i32,
}

impl TlObject for KeysGetPeerPackages {
    const CTOR: u32 = 0x52e2d50b;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.user_id);
        e.int(self.limit);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let user_id = d.long()?;
        let limit = d.int()?;
        d.leave();
        Ok(Self {
            user_id,
            limit,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysGetPeerVerification {
    pub user_id: i64,
}

impl TlObject for KeysGetPeerVerification {
    const CTOR: u32 = 0x4d297c18;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.user_id);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let user_id = d.long()?;
        d.leave();
        Ok(Self {
            user_id,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysGetTransparency {
    pub user_id: i64,
    pub device_id: i64,
    pub pinned_to_sequence: Option<i64>,
    pub pinned_root_hash: Option<Vec<u8>>,
    pub limit: i32,
}

impl TlObject for KeysGetTransparency {
    const CTOR: u32 = 0x6fae2c19;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        let mut flags = crate::Flags(0);
        flags = flags.set(0, self.pinned_to_sequence.is_some());
        flags = flags.set(1, self.pinned_root_hash.is_some());
        e.uint(flags.0);
        e.long(self.user_id);
        e.long(self.device_id);
        if let Some(__v) = &self.pinned_to_sequence {
            e.long(*__v);
        }
        if let Some(__v) = &self.pinned_root_hash {
            e.bytes(__v)?;
        }
        e.int(self.limit);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let flags = crate::Flags(d.uint()?);
        let user_id = d.long()?;
        let device_id = d.long()?;
        let pinned_to_sequence = if flags.has(0) { Some(d.long()?) } else { None };
        let pinned_root_hash = if flags.has(1) { Some(d.bytes()?) } else { None };
        let limit = d.int()?;
        d.leave();
        Ok(Self {
            user_id,
            device_id,
            pinned_to_sequence,
            pinned_root_hash,
            limit,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysIdentityPin {
    pub user_id: i64,
    pub pinned_commitment: Vec<u8>,
    pub current_commitment: Vec<u8>,
    pub safety_number: String,
    pub status: String,
    pub pinned_at: i64,
    pub updated_at: i64,
    pub pinned_roster_epoch: i64,
    pub current_roster_epoch: i64,
    pub pinned_device_count: i32,
    pub current_device_count: i32,
    pub pinned_tombstone_count: i32,
    pub current_tombstone_count: i32,
    pub pinned_roster_proof_hash: Vec<u8>,
    pub current_roster_proof_hash: Vec<u8>,
    pub ux_action: String,
    pub change_reason: String,
}

impl TlObject for KeysIdentityPin {
    const CTOR: u32 = 0x9bd4a621;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.user_id);
        e.bytes(&self.pinned_commitment)?;
        e.bytes(&self.current_commitment)?;
        e.string(&self.safety_number)?;
        e.string(&self.status)?;
        e.long(self.pinned_at);
        e.long(self.updated_at);
        e.long(self.pinned_roster_epoch);
        e.long(self.current_roster_epoch);
        e.int(self.pinned_device_count);
        e.int(self.current_device_count);
        e.int(self.pinned_tombstone_count);
        e.int(self.current_tombstone_count);
        e.bytes(&self.pinned_roster_proof_hash)?;
        e.bytes(&self.current_roster_proof_hash)?;
        e.string(&self.ux_action)?;
        e.string(&self.change_reason)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let user_id = d.long()?;
        let pinned_commitment = d.bytes()?;
        let current_commitment = d.bytes()?;
        let safety_number = d.string()?;
        let status = d.string()?;
        let pinned_at = d.long()?;
        let updated_at = d.long()?;
        let pinned_roster_epoch = d.long()?;
        let current_roster_epoch = d.long()?;
        let pinned_device_count = d.int()?;
        let current_device_count = d.int()?;
        let pinned_tombstone_count = d.int()?;
        let current_tombstone_count = d.int()?;
        let pinned_roster_proof_hash = d.bytes()?;
        let current_roster_proof_hash = d.bytes()?;
        let ux_action = d.string()?;
        let change_reason = d.string()?;
        d.leave();
        Ok(Self {
            user_id,
            pinned_commitment,
            current_commitment,
            safety_number,
            status,
            pinned_at,
            updated_at,
            pinned_roster_epoch,
            current_roster_epoch,
            pinned_device_count,
            current_device_count,
            pinned_tombstone_count,
            current_tombstone_count,
            pinned_roster_proof_hash,
            current_roster_proof_hash,
            ux_action,
            change_reason,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysIdentitySnapshot {
    pub user_id: i64,
    pub commitment: Vec<u8>,
    pub roster_epoch: i64,
    pub generated_at: i64,
    pub devices: Vec<IdentityDeviceState>,
    pub proof: Vec<u8>,
}

impl TlObject for KeysIdentitySnapshot {
    const CTOR: u32 = 0x5b9a7482;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.user_id);
        e.bytes(&self.commitment)?;
        e.long(self.roster_epoch);
        e.long(self.generated_at);
        {
            let __v = &self.devices;
            e.vector_header(__v.len())?;
            for __x in __v {
                __x.encode(e)?;
            }
        }
        e.bytes(&self.proof)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let user_id = d.long()?;
        let commitment = d.bytes()?;
        let roster_epoch = d.long()?;
        let generated_at = d.long()?;
        let devices = {
            let __n = d.vector_header()?;
            let mut __v = Vec::with_capacity(__n);
            for _ in 0..__n {
                __v.push(IdentityDeviceState::decode(d)?);
            }
            __v
        };
        let proof = d.bytes()?;
        d.leave();
        Ok(Self {
            user_id,
            commitment,
            roster_epoch,
            generated_at,
            devices,
            proof,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysIdentityVerification {
    pub user_id: i64,
    pub commitment: Vec<u8>,
    pub safety_number: String,
    pub generated_at: i64,
    pub roster_epoch: i64,
    pub device_count: i32,
    pub tombstone_count: i32,
    pub roster_proof_hash: Vec<u8>,
    pub ux_action: String,
    pub change_reason: String,
}

impl TlObject for KeysIdentityVerification {
    const CTOR: u32 = 0x28d0ec66;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.user_id);
        e.bytes(&self.commitment)?;
        e.string(&self.safety_number)?;
        e.long(self.generated_at);
        e.long(self.roster_epoch);
        e.int(self.device_count);
        e.int(self.tombstone_count);
        e.bytes(&self.roster_proof_hash)?;
        e.string(&self.ux_action)?;
        e.string(&self.change_reason)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let user_id = d.long()?;
        let commitment = d.bytes()?;
        let safety_number = d.string()?;
        let generated_at = d.long()?;
        let roster_epoch = d.long()?;
        let device_count = d.int()?;
        let tombstone_count = d.int()?;
        let roster_proof_hash = d.bytes()?;
        let ux_action = d.string()?;
        let change_reason = d.string()?;
        d.leave();
        Ok(Self {
            user_id,
            commitment,
            safety_number,
            generated_at,
            roster_epoch,
            device_count,
            tombstone_count,
            roster_proof_hash,
            ux_action,
            change_reason,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysPackage {
    pub package_id: String,
    pub device_id: i64,
    pub kind: String,
    pub schema: String,
    pub suite: String,
    pub payload: Vec<u8>,
    pub metadata: Vec<u8>,
    pub published_at: i64,
    pub expires_at: i64,
}

impl TlObject for KeysPackage {
    const CTOR: u32 = 0x6f4f86a1;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.string(&self.package_id)?;
        e.long(self.device_id);
        e.string(&self.kind)?;
        e.string(&self.schema)?;
        e.string(&self.suite)?;
        e.bytes(&self.payload)?;
        e.bytes(&self.metadata)?;
        e.long(self.published_at);
        e.long(self.expires_at);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let package_id = d.string()?;
        let device_id = d.long()?;
        let kind = d.string()?;
        let schema = d.string()?;
        let suite = d.string()?;
        let payload = d.bytes()?;
        let metadata = d.bytes()?;
        let published_at = d.long()?;
        let expires_at = d.long()?;
        d.leave();
        Ok(Self {
            package_id,
            device_id,
            kind,
            schema,
            suite,
            payload,
            metadata,
            published_at,
            expires_at,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysPackageStored {
    pub package_id: String,
    pub published_at: i64,
    pub expires_at: i64,
}

impl TlObject for KeysPackageStored {
    const CTOR: u32 = 0x19b4303c;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.string(&self.package_id)?;
        e.long(self.published_at);
        e.long(self.expires_at);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let package_id = d.string()?;
        let published_at = d.long()?;
        let expires_at = d.long()?;
        d.leave();
        Ok(Self {
            package_id,
            published_at,
            expires_at,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysPeerBundle {
    pub user_id: i64,
    pub devices: Vec<DevicePrekeyBundle>,
}

impl TlObject for KeysPeerBundle {
    const CTOR: u32 = 0xb1683ff2;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.user_id);
        {
            let __v = &self.devices;
            e.vector_header(__v.len())?;
            for __x in __v {
                __x.encode(e)?;
            }
        }
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let user_id = d.long()?;
        let devices = {
            let __n = d.vector_header()?;
            let mut __v = Vec::with_capacity(__n);
            for _ in 0..__n {
                __v.push(DevicePrekeyBundle::decode(d)?);
            }
            __v
        };
        d.leave();
        Ok(Self {
            user_id,
            devices,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysPeerPackages {
    pub user_id: i64,
    pub items: Vec<KeysPackage>,
}

impl TlObject for KeysPeerPackages {
    const CTOR: u32 = 0x7cc59702;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.user_id);
        {
            let __v = &self.items;
            e.vector_header(__v.len())?;
            for __x in __v {
                __x.encode(e)?;
            }
        }
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let user_id = d.long()?;
        let items = {
            let __n = d.vector_header()?;
            let mut __v = Vec::with_capacity(__n);
            for _ in 0..__n {
                __v.push(KeysPackage::decode(d)?);
            }
            __v
        };
        d.leave();
        Ok(Self {
            user_id,
            items,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysPinIdentity {
    pub user_id: i64,
    pub commitment: Vec<u8>,
}

impl TlObject for KeysPinIdentity {
    const CTOR: u32 = 0xde7e494c;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.user_id);
        e.bytes(&self.commitment)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let user_id = d.long()?;
        let commitment = d.bytes()?;
        d.leave();
        Ok(Self {
            user_id,
            commitment,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysPutArtifact {
    pub client_ref: String,
    pub recipient_device_id: i64,
    pub kind: String,
    pub schema: String,
    pub ciphertext: Vec<u8>,
    pub metadata: Vec<u8>,
    pub expires_in: i32,
}

impl TlObject for KeysPutArtifact {
    const CTOR: u32 = 0x6a7e4f21;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.string(&self.client_ref)?;
        e.long(self.recipient_device_id);
        e.string(&self.kind)?;
        e.string(&self.schema)?;
        e.bytes(&self.ciphertext)?;
        e.bytes(&self.metadata)?;
        e.int(self.expires_in);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let client_ref = d.string()?;
        let recipient_device_id = d.long()?;
        let kind = d.string()?;
        let schema = d.string()?;
        let ciphertext = d.bytes()?;
        let metadata = d.bytes()?;
        let expires_in = d.int()?;
        d.leave();
        Ok(Self {
            client_ref,
            recipient_device_id,
            kind,
            schema,
            ciphertext,
            metadata,
            expires_in,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysPutPackage {
    pub client_ref: String,
    pub kind: String,
    pub schema: String,
    pub suite: String,
    pub payload: Vec<u8>,
    pub metadata: Vec<u8>,
    pub expires_in: i32,
}

impl TlObject for KeysPutPackage {
    const CTOR: u32 = 0x3ebbf310;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.string(&self.client_ref)?;
        e.string(&self.kind)?;
        e.string(&self.schema)?;
        e.string(&self.suite)?;
        e.bytes(&self.payload)?;
        e.bytes(&self.metadata)?;
        e.int(self.expires_in);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let client_ref = d.string()?;
        let kind = d.string()?;
        let schema = d.string()?;
        let suite = d.string()?;
        let payload = d.bytes()?;
        let metadata = d.bytes()?;
        let expires_in = d.int()?;
        d.leave();
        Ok(Self {
            client_ref,
            kind,
            schema,
            suite,
            payload,
            metadata,
            expires_in,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysSetCapabilities {
    pub features: Vec<String>,
}

impl TlObject for KeysSetCapabilities {
    const CTOR: u32 = 0x54ac9b32;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        {
            let __v = &self.features;
            e.vector_header(__v.len())?;
            for __x in __v {
                e.string(__x)?;
            }
        }
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let features = {
            let __n = d.vector_header()?;
            let mut __v = Vec::with_capacity(__n);
            for _ in 0..__n {
                __v.push(d.string()?);
            }
            __v
        };
        d.leave();
        Ok(Self {
            features,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysSetDeviceSigningKey {
    pub public_key: Vec<u8>,
}

impl TlObject for KeysSetDeviceSigningKey {
    const CTOR: u32 = 0x174a3131;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.bytes(&self.public_key)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let public_key = d.bytes()?;
        d.leave();
        Ok(Self {
            public_key,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysStatus {
    pub device_id: i64,
    pub signed_pre_key_id: i32,
    pub signed_pre_key_updated_at: i64,
    pub signed_pre_key_rotate_after: i64,
    pub remaining_one_time: i32,
    pub low_watermark: bool,
    pub needs_signed_pre_key_rotation: bool,
    pub target_one_time: i32,
    pub max_one_time: i32,
    pub updated_at: i64,
}

impl TlObject for KeysStatus {
    const CTOR: u32 = 0x8cf9b221;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.device_id);
        e.int(self.signed_pre_key_id);
        e.long(self.signed_pre_key_updated_at);
        e.long(self.signed_pre_key_rotate_after);
        e.int(self.remaining_one_time);
        e.bool(self.low_watermark);
        e.bool(self.needs_signed_pre_key_rotation);
        e.int(self.target_one_time);
        e.int(self.max_one_time);
        e.long(self.updated_at);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let device_id = d.long()?;
        let signed_pre_key_id = d.int()?;
        let signed_pre_key_updated_at = d.long()?;
        let signed_pre_key_rotate_after = d.long()?;
        let remaining_one_time = d.int()?;
        let low_watermark = d.bool()?;
        let needs_signed_pre_key_rotation = d.bool()?;
        let target_one_time = d.int()?;
        let max_one_time = d.int()?;
        let updated_at = d.long()?;
        d.leave();
        Ok(Self {
            device_id,
            signed_pre_key_id,
            signed_pre_key_updated_at,
            signed_pre_key_rotate_after,
            remaining_one_time,
            low_watermark,
            needs_signed_pre_key_rotation,
            target_one_time,
            max_one_time,
            updated_at,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysTransparencyCheckpoint {
    pub user_id: i64,
    pub device_id: i64,
    pub from_sequence: i64,
    pub to_sequence: i64,
    pub entry_count: i32,
    pub root_hash: Vec<u8>,
    pub latest_entry_hash: Vec<u8>,
    pub generated_at: i64,
    pub signature_scheme: String,
    pub signing_public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl TlObject for KeysTransparencyCheckpoint {
    const CTOR: u32 = 0x4b8f01c2;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.user_id);
        e.long(self.device_id);
        e.long(self.from_sequence);
        e.long(self.to_sequence);
        e.int(self.entry_count);
        e.bytes(&self.root_hash)?;
        e.bytes(&self.latest_entry_hash)?;
        e.long(self.generated_at);
        e.string(&self.signature_scheme)?;
        e.bytes(&self.signing_public_key)?;
        e.bytes(&self.signature)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let user_id = d.long()?;
        let device_id = d.long()?;
        let from_sequence = d.long()?;
        let to_sequence = d.long()?;
        let entry_count = d.int()?;
        let root_hash = d.bytes()?;
        let latest_entry_hash = d.bytes()?;
        let generated_at = d.long()?;
        let signature_scheme = d.string()?;
        let signing_public_key = d.bytes()?;
        let signature = d.bytes()?;
        d.leave();
        Ok(Self {
            user_id,
            device_id,
            from_sequence,
            to_sequence,
            entry_count,
            root_hash,
            latest_entry_hash,
            generated_at,
            signature_scheme,
            signing_public_key,
            signature,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysTransparencyConsistencyProof {
    pub user_id: i64,
    pub device_id: i64,
    pub from_sequence: i64,
    pub to_sequence: i64,
    pub from_root_hash: Vec<u8>,
    pub to_root_hash: Vec<u8>,
    pub suffix_entry_hashes: Vec<Vec<u8>>,
}

impl TlObject for KeysTransparencyConsistencyProof {
    const CTOR: u32 = 0x77ad1f42;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.user_id);
        e.long(self.device_id);
        e.long(self.from_sequence);
        e.long(self.to_sequence);
        e.bytes(&self.from_root_hash)?;
        e.bytes(&self.to_root_hash)?;
        {
            let __v = &self.suffix_entry_hashes;
            e.vector_header(__v.len())?;
            for __x in __v {
                e.bytes(__x)?;
            }
        }
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let user_id = d.long()?;
        let device_id = d.long()?;
        let from_sequence = d.long()?;
        let to_sequence = d.long()?;
        let from_root_hash = d.bytes()?;
        let to_root_hash = d.bytes()?;
        let suffix_entry_hashes = {
            let __n = d.vector_header()?;
            let mut __v = Vec::with_capacity(__n);
            for _ in 0..__n {
                __v.push(d.bytes()?);
            }
            __v
        };
        d.leave();
        Ok(Self {
            user_id,
            device_id,
            from_sequence,
            to_sequence,
            from_root_hash,
            to_root_hash,
            suffix_entry_hashes,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysTransparencyEntry {
    pub user_id: i64,
    pub device_id: i64,
    pub sequence: i64,
    pub event: String,
    pub identity_key: Vec<u8>,
    pub signed_pre_key_id: i32,
    pub signed_pre_key_pub: Vec<u8>,
    pub signed_pre_key_sig: Vec<u8>,
    pub device_signing_key: Vec<u8>,
    pub prev_hash: Vec<u8>,
    pub entry_hash: Vec<u8>,
    pub created_at: i64,
}

impl TlObject for KeysTransparencyEntry {
    const CTOR: u32 = 0x32569df4;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.user_id);
        e.long(self.device_id);
        e.long(self.sequence);
        e.string(&self.event)?;
        e.bytes(&self.identity_key)?;
        e.int(self.signed_pre_key_id);
        e.bytes(&self.signed_pre_key_pub)?;
        e.bytes(&self.signed_pre_key_sig)?;
        e.bytes(&self.device_signing_key)?;
        e.bytes(&self.prev_hash)?;
        e.bytes(&self.entry_hash)?;
        e.long(self.created_at);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let user_id = d.long()?;
        let device_id = d.long()?;
        let sequence = d.long()?;
        let event = d.string()?;
        let identity_key = d.bytes()?;
        let signed_pre_key_id = d.int()?;
        let signed_pre_key_pub = d.bytes()?;
        let signed_pre_key_sig = d.bytes()?;
        let device_signing_key = d.bytes()?;
        let prev_hash = d.bytes()?;
        let entry_hash = d.bytes()?;
        let created_at = d.long()?;
        d.leave();
        Ok(Self {
            user_id,
            device_id,
            sequence,
            event,
            identity_key,
            signed_pre_key_id,
            signed_pre_key_pub,
            signed_pre_key_sig,
            device_signing_key,
            prev_hash,
            entry_hash,
            created_at,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysTransparencyLog {
    pub user_id: i64,
    pub device_id: i64,
    pub items: Vec<KeysTransparencyEntry>,
    pub checkpoint: KeysTransparencyCheckpoint,
    pub consistency_proof: KeysTransparencyConsistencyProof,
    pub witnesses: Vec<KeysTransparencyWitnessSignature>,
}

impl TlObject for KeysTransparencyLog {
    const CTOR: u32 = 0x1a5c9e23;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.user_id);
        e.long(self.device_id);
        {
            let __v = &self.items;
            e.vector_header(__v.len())?;
            for __x in __v {
                __x.encode(e)?;
            }
        }
        self.checkpoint.encode(e)?;
        self.consistency_proof.encode(e)?;
        {
            let __v = &self.witnesses;
            e.vector_header(__v.len())?;
            for __x in __v {
                __x.encode(e)?;
            }
        }
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let user_id = d.long()?;
        let device_id = d.long()?;
        let items = {
            let __n = d.vector_header()?;
            let mut __v = Vec::with_capacity(__n);
            for _ in 0..__n {
                __v.push(KeysTransparencyEntry::decode(d)?);
            }
            __v
        };
        let checkpoint = KeysTransparencyCheckpoint::decode(d)?;
        let consistency_proof = KeysTransparencyConsistencyProof::decode(d)?;
        let witnesses = {
            let __n = d.vector_header()?;
            let mut __v = Vec::with_capacity(__n);
            for _ in 0..__n {
                __v.push(KeysTransparencyWitnessSignature::decode(d)?);
            }
            __v
        };
        d.leave();
        Ok(Self {
            user_id,
            device_id,
            items,
            checkpoint,
            consistency_proof,
            witnesses,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysTransparencyWitnessSignature {
    pub user_id: i64,
    pub device_id: i64,
    pub to_sequence: i64,
    pub root_hash: Vec<u8>,
    pub checkpoint_signature_hash: Vec<u8>,
    pub witness_id: String,
    pub witness_public_key: Vec<u8>,
    pub signed_at: i64,
    pub signature_scheme: String,
    pub signature: Vec<u8>,
}

impl TlObject for KeysTransparencyWitnessSignature {
    const CTOR: u32 = 0x4f2c0b67;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.user_id);
        e.long(self.device_id);
        e.long(self.to_sequence);
        e.bytes(&self.root_hash)?;
        e.bytes(&self.checkpoint_signature_hash)?;
        e.string(&self.witness_id)?;
        e.bytes(&self.witness_public_key)?;
        e.long(self.signed_at);
        e.string(&self.signature_scheme)?;
        e.bytes(&self.signature)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let user_id = d.long()?;
        let device_id = d.long()?;
        let to_sequence = d.long()?;
        let root_hash = d.bytes()?;
        let checkpoint_signature_hash = d.bytes()?;
        let witness_id = d.string()?;
        let witness_public_key = d.bytes()?;
        let signed_at = d.long()?;
        let signature_scheme = d.string()?;
        let signature = d.bytes()?;
        d.leave();
        Ok(Self {
            user_id,
            device_id,
            to_sequence,
            root_hash,
            checkpoint_signature_hash,
            witness_id,
            witness_public_key,
            signed_at,
            signature_scheme,
            signature,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysUpload {
    pub identity_key: Vec<u8>,
    pub signed_pre_key_id: i32,
    pub signed_pre_key_pub: Vec<u8>,
    pub signed_pre_key_sig: Vec<u8>,
    pub one_time_pre_keys: Vec<OneTimePreKey>,
}

impl TlObject for KeysUpload {
    const CTOR: u32 = 0x83d1bc90;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.bytes(&self.identity_key)?;
        e.int(self.signed_pre_key_id);
        e.bytes(&self.signed_pre_key_pub)?;
        e.bytes(&self.signed_pre_key_sig)?;
        {
            let __v = &self.one_time_pre_keys;
            e.vector_header(__v.len())?;
            for __x in __v {
                __x.encode(e)?;
            }
        }
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let identity_key = d.bytes()?;
        let signed_pre_key_id = d.int()?;
        let signed_pre_key_pub = d.bytes()?;
        let signed_pre_key_sig = d.bytes()?;
        let one_time_pre_keys = {
            let __n = d.vector_header()?;
            let mut __v = Vec::with_capacity(__n);
            for _ in 0..__n {
                __v.push(OneTimePreKey::decode(d)?);
            }
            __v
        };
        d.leave();
        Ok(Self {
            identity_key,
            signed_pre_key_id,
            signed_pre_key_pub,
            signed_pre_key_sig,
            one_time_pre_keys,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct KeysUploaded {
    pub device_id: i64,
    pub signed_pre_key_id: i32,
    pub signed_pre_key_updated_at: i64,
    pub signed_pre_key_rotate_after: i64,
    pub remaining_one_time: i32,
    pub low_watermark: bool,
    pub needs_signed_pre_key_rotation: bool,
    pub target_one_time: i32,
    pub max_one_time: i32,
    pub updated_at: i64,
}

impl TlObject for KeysUploaded {
    const CTOR: u32 = 0x90d4ea61;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.device_id);
        e.int(self.signed_pre_key_id);
        e.long(self.signed_pre_key_updated_at);
        e.long(self.signed_pre_key_rotate_after);
        e.int(self.remaining_one_time);
        e.bool(self.low_watermark);
        e.bool(self.needs_signed_pre_key_rotation);
        e.int(self.target_one_time);
        e.int(self.max_one_time);
        e.long(self.updated_at);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let device_id = d.long()?;
        let signed_pre_key_id = d.int()?;
        let signed_pre_key_updated_at = d.long()?;
        let signed_pre_key_rotate_after = d.long()?;
        let remaining_one_time = d.int()?;
        let low_watermark = d.bool()?;
        let needs_signed_pre_key_rotation = d.bool()?;
        let target_one_time = d.int()?;
        let max_one_time = d.int()?;
        let updated_at = d.long()?;
        d.leave();
        Ok(Self {
            device_id,
            signed_pre_key_id,
            signed_pre_key_updated_at,
            signed_pre_key_rotate_after,
            remaining_one_time,
            low_watermark,
            needs_signed_pre_key_rotation,
            target_one_time,
            max_one_time,
            updated_at,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MessageAssociatedData {
    pub schema: String,
    pub suite: String,
    pub crypto_policy_profile: String,
    pub crypto_policy_version: i32,
    pub crypto_policy_sha256: String,
    pub sender_user_id: i64,
    pub sender_device_id: i64,
    pub chat_id: i64,
    pub client_msg_id: String,
    pub forward_info_sha256: Option<String>,
    pub reply_to: Option<i64>,
}

impl TlObject for MessageAssociatedData {
    const CTOR: u32 = 0xe2ee0001;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        let mut flags = crate::Flags(0);
        flags = flags.set(0, self.forward_info_sha256.is_some());
        flags = flags.set(1, self.reply_to.is_some());
        e.uint(flags.0);
        e.string(&self.schema)?;
        e.string(&self.suite)?;
        e.string(&self.crypto_policy_profile)?;
        e.int(self.crypto_policy_version);
        e.string(&self.crypto_policy_sha256)?;
        e.long(self.sender_user_id);
        e.long(self.sender_device_id);
        e.long(self.chat_id);
        e.string(&self.client_msg_id)?;
        if let Some(__v) = &self.forward_info_sha256 {
            e.string(__v)?;
        }
        if let Some(__v) = &self.reply_to {
            e.long(*__v);
        }
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let flags = crate::Flags(d.uint()?);
        let schema = d.string()?;
        let suite = d.string()?;
        let crypto_policy_profile = d.string()?;
        let crypto_policy_version = d.int()?;
        let crypto_policy_sha256 = d.string()?;
        let sender_user_id = d.long()?;
        let sender_device_id = d.long()?;
        let chat_id = d.long()?;
        let client_msg_id = d.string()?;
        let forward_info_sha256 = if flags.has(0) { Some(d.string()?) } else { None };
        let reply_to = if flags.has(1) { Some(d.long()?) } else { None };
        d.leave();
        Ok(Self {
            schema,
            suite,
            crypto_policy_profile,
            crypto_policy_version,
            crypto_policy_sha256,
            sender_user_id,
            sender_device_id,
            chat_id,
            client_msg_id,
            forward_info_sha256,
            reply_to,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MessageEnvelopeHeaderV2 {
    pub schema: String,
    pub suite: String,
    pub crypto_policy_profile: String,
    pub crypto_policy_version: i32,
    pub crypto_policy_sha256: String,
    pub envelope_type: String,
    pub sender_user_id: i64,
    pub sender_device_id: i64,
    pub recipient_user_id: i64,
    pub recipient_device_id: i64,
    pub chat_id: i64,
    pub client_msg_id: String,
    pub associated_data_sha256: String,
    pub ciphertext_sha256: String,
    pub message_nonce: String,
}

impl TlObject for MessageEnvelopeHeaderV2 {
    const CTOR: u32 = 0xe2ee0005;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.string(&self.schema)?;
        e.string(&self.suite)?;
        e.string(&self.crypto_policy_profile)?;
        e.int(self.crypto_policy_version);
        e.string(&self.crypto_policy_sha256)?;
        e.string(&self.envelope_type)?;
        e.long(self.sender_user_id);
        e.long(self.sender_device_id);
        e.long(self.recipient_user_id);
        e.long(self.recipient_device_id);
        e.long(self.chat_id);
        e.string(&self.client_msg_id)?;
        e.string(&self.associated_data_sha256)?;
        e.string(&self.ciphertext_sha256)?;
        e.string(&self.message_nonce)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let schema = d.string()?;
        let suite = d.string()?;
        let crypto_policy_profile = d.string()?;
        let crypto_policy_version = d.int()?;
        let crypto_policy_sha256 = d.string()?;
        let envelope_type = d.string()?;
        let sender_user_id = d.long()?;
        let sender_device_id = d.long()?;
        let recipient_user_id = d.long()?;
        let recipient_device_id = d.long()?;
        let chat_id = d.long()?;
        let client_msg_id = d.string()?;
        let associated_data_sha256 = d.string()?;
        let ciphertext_sha256 = d.string()?;
        let message_nonce = d.string()?;
        d.leave();
        Ok(Self {
            schema,
            suite,
            crypto_policy_profile,
            crypto_policy_version,
            crypto_policy_sha256,
            envelope_type,
            sender_user_id,
            sender_device_id,
            recipient_user_id,
            recipient_device_id,
            chat_id,
            client_msg_id,
            associated_data_sha256,
            ciphertext_sha256,
            message_nonce,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MessageEnvelopeHeaderV3 {
    pub schema: String,
    pub suite: String,
    pub crypto_policy_profile: String,
    pub crypto_policy_version: i32,
    pub crypto_policy_sha256: String,
    pub envelope_type: String,
    pub sender_user_id: i64,
    pub sender_device_id: i64,
    pub recipient_user_id: i64,
    pub recipient_device_id: i64,
    pub chat_id: i64,
    pub client_msg_id: String,
    pub associated_data_sha256: String,
    pub ciphertext_sha256: String,
    pub message_nonce: String,
    pub signal_session_bootstrap: SignalSessionBootstrapContract,
    pub signal_session_bootstrap_sha256: String,
}

impl TlObject for MessageEnvelopeHeaderV3 {
    const CTOR: u32 = 0xe2ee0006;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.string(&self.schema)?;
        e.string(&self.suite)?;
        e.string(&self.crypto_policy_profile)?;
        e.int(self.crypto_policy_version);
        e.string(&self.crypto_policy_sha256)?;
        e.string(&self.envelope_type)?;
        e.long(self.sender_user_id);
        e.long(self.sender_device_id);
        e.long(self.recipient_user_id);
        e.long(self.recipient_device_id);
        e.long(self.chat_id);
        e.string(&self.client_msg_id)?;
        e.string(&self.associated_data_sha256)?;
        e.string(&self.ciphertext_sha256)?;
        e.string(&self.message_nonce)?;
        self.signal_session_bootstrap.encode(e)?;
        e.string(&self.signal_session_bootstrap_sha256)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let schema = d.string()?;
        let suite = d.string()?;
        let crypto_policy_profile = d.string()?;
        let crypto_policy_version = d.int()?;
        let crypto_policy_sha256 = d.string()?;
        let envelope_type = d.string()?;
        let sender_user_id = d.long()?;
        let sender_device_id = d.long()?;
        let recipient_user_id = d.long()?;
        let recipient_device_id = d.long()?;
        let chat_id = d.long()?;
        let client_msg_id = d.string()?;
        let associated_data_sha256 = d.string()?;
        let ciphertext_sha256 = d.string()?;
        let message_nonce = d.string()?;
        let signal_session_bootstrap = SignalSessionBootstrapContract::decode(d)?;
        let signal_session_bootstrap_sha256 = d.string()?;
        d.leave();
        Ok(Self {
            schema,
            suite,
            crypto_policy_profile,
            crypto_policy_version,
            crypto_policy_sha256,
            envelope_type,
            sender_user_id,
            sender_device_id,
            recipient_user_id,
            recipient_device_id,
            chat_id,
            client_msg_id,
            associated_data_sha256,
            ciphertext_sha256,
            message_nonce,
            signal_session_bootstrap,
            signal_session_bootstrap_sha256,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MessageEnvelopeHeaderV4 {
    pub schema: String,
    pub suite: String,
    pub crypto_policy_profile: String,
    pub crypto_policy_version: i32,
    pub crypto_policy_sha256: String,
    pub envelope_type: String,
    pub sender_user_id: i64,
    pub sender_device_id: i64,
    pub recipient_user_id: i64,
    pub recipient_device_id: i64,
    pub chat_id: i64,
    pub client_msg_id: String,
    pub associated_data_sha256: String,
    pub ciphertext_sha256: String,
    pub message_nonce: String,
    pub sender_key_group_membership: SenderKeyGroupMembershipContract,
    pub sender_key_group_membership_sha256: String,
}

impl TlObject for MessageEnvelopeHeaderV4 {
    const CTOR: u32 = 0xe2ee0007;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.string(&self.schema)?;
        e.string(&self.suite)?;
        e.string(&self.crypto_policy_profile)?;
        e.int(self.crypto_policy_version);
        e.string(&self.crypto_policy_sha256)?;
        e.string(&self.envelope_type)?;
        e.long(self.sender_user_id);
        e.long(self.sender_device_id);
        e.long(self.recipient_user_id);
        e.long(self.recipient_device_id);
        e.long(self.chat_id);
        e.string(&self.client_msg_id)?;
        e.string(&self.associated_data_sha256)?;
        e.string(&self.ciphertext_sha256)?;
        e.string(&self.message_nonce)?;
        self.sender_key_group_membership.encode(e)?;
        e.string(&self.sender_key_group_membership_sha256)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let schema = d.string()?;
        let suite = d.string()?;
        let crypto_policy_profile = d.string()?;
        let crypto_policy_version = d.int()?;
        let crypto_policy_sha256 = d.string()?;
        let envelope_type = d.string()?;
        let sender_user_id = d.long()?;
        let sender_device_id = d.long()?;
        let recipient_user_id = d.long()?;
        let recipient_device_id = d.long()?;
        let chat_id = d.long()?;
        let client_msg_id = d.string()?;
        let associated_data_sha256 = d.string()?;
        let ciphertext_sha256 = d.string()?;
        let message_nonce = d.string()?;
        let sender_key_group_membership = SenderKeyGroupMembershipContract::decode(d)?;
        let sender_key_group_membership_sha256 = d.string()?;
        d.leave();
        Ok(Self {
            schema,
            suite,
            crypto_policy_profile,
            crypto_policy_version,
            crypto_policy_sha256,
            envelope_type,
            sender_user_id,
            sender_device_id,
            recipient_user_id,
            recipient_device_id,
            chat_id,
            client_msg_id,
            associated_data_sha256,
            ciphertext_sha256,
            message_nonce,
            sender_key_group_membership,
            sender_key_group_membership_sha256,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MessagesAckEncrypted {
    pub server_msg_id: String,
}

impl TlObject for MessagesAckEncrypted {
    const CTOR: u32 = 0x2a6d9e40;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.string(&self.server_msg_id)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let server_msg_id = d.string()?;
        d.leave();
        Ok(Self {
            server_msg_id,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MessagesEncryptedAcked {
    pub server_msg_id: String,
    pub deleted: bool,
}

impl TlObject for MessagesEncryptedAcked {
    const CTOR: u32 = 0xc21bb93e;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.string(&self.server_msg_id)?;
        e.bool(self.deleted);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let server_msg_id = d.string()?;
        let deleted = d.bool()?;
        d.leave();
        Ok(Self {
            server_msg_id,
            deleted,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MessagesEncryptedBatch {
    pub items: Vec<MessagesEncryptedDelivery>,
}

impl TlObject for MessagesEncryptedBatch {
    const CTOR: u32 = 0x7862cfa1;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        {
            let __v = &self.items;
            e.vector_header(__v.len())?;
            for __x in __v {
                __x.encode(e)?;
            }
        }
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let items = {
            let __n = d.vector_header()?;
            let mut __v = Vec::with_capacity(__n);
            for _ in 0..__n {
                __v.push(MessagesEncryptedDelivery::decode(d)?);
            }
            __v
        };
        d.leave();
        Ok(Self {
            items,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MessagesEncryptedDelivery {
    pub server_msg_id: String,
    pub sender_user_id: i64,
    pub sender_device_id: i64,
    pub chat_id: i64,
    pub client_msg_id: String,
    pub schema: String,
    pub suite: String,
    pub envelope_type: String,
    pub header: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub associated_data: Vec<u8>,
    pub forward_info: Option<Vec<u8>>,
    pub reply_to: Option<i64>,
    pub proof: Vec<u8>,
    pub created_at: i64,
}

impl TlObject for MessagesEncryptedDelivery {
    const CTOR: u32 = 0x9ad41c33;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        let mut flags = crate::Flags(0);
        flags = flags.set(0, self.forward_info.is_some());
        flags = flags.set(1, self.reply_to.is_some());
        e.uint(flags.0);
        e.string(&self.server_msg_id)?;
        e.long(self.sender_user_id);
        e.long(self.sender_device_id);
        e.long(self.chat_id);
        e.string(&self.client_msg_id)?;
        e.string(&self.schema)?;
        e.string(&self.suite)?;
        e.string(&self.envelope_type)?;
        e.bytes(&self.header)?;
        e.bytes(&self.ciphertext)?;
        e.bytes(&self.associated_data)?;
        if let Some(__v) = &self.forward_info {
            e.bytes(__v)?;
        }
        if let Some(__v) = &self.reply_to {
            e.long(*__v);
        }
        e.bytes(&self.proof)?;
        e.long(self.created_at);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let flags = crate::Flags(d.uint()?);
        let server_msg_id = d.string()?;
        let sender_user_id = d.long()?;
        let sender_device_id = d.long()?;
        let chat_id = d.long()?;
        let client_msg_id = d.string()?;
        let schema = d.string()?;
        let suite = d.string()?;
        let envelope_type = d.string()?;
        let header = d.bytes()?;
        let ciphertext = d.bytes()?;
        let associated_data = d.bytes()?;
        let forward_info = if flags.has(0) { Some(d.bytes()?) } else { None };
        let reply_to = if flags.has(1) { Some(d.long()?) } else { None };
        let proof = d.bytes()?;
        let created_at = d.long()?;
        d.leave();
        Ok(Self {
            server_msg_id,
            sender_user_id,
            sender_device_id,
            chat_id,
            client_msg_id,
            schema,
            suite,
            envelope_type,
            header,
            ciphertext,
            associated_data,
            forward_info,
            reply_to,
            proof,
            created_at,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MessagesEncryptedRecipient {
    pub user_id: i64,
    pub device_id: i64,
    pub envelope_type: String,
    pub header: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl TlObject for MessagesEncryptedRecipient {
    const CTOR: u32 = 0x0a18c641;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.user_id);
        e.long(self.device_id);
        e.string(&self.envelope_type)?;
        e.bytes(&self.header)?;
        e.bytes(&self.ciphertext)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let user_id = d.long()?;
        let device_id = d.long()?;
        let envelope_type = d.string()?;
        let header = d.bytes()?;
        let ciphertext = d.bytes()?;
        d.leave();
        Ok(Self {
            user_id,
            device_id,
            envelope_type,
            header,
            ciphertext,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MessagesEncryptedSent {
    pub server_msg_id: String,
    pub created_at: i64,
    pub recipient_count: i32,
}

impl TlObject for MessagesEncryptedSent {
    const CTOR: u32 = 0x54dc2ff4;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.string(&self.server_msg_id)?;
        e.long(self.created_at);
        e.int(self.recipient_count);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let server_msg_id = d.string()?;
        let created_at = d.long()?;
        let recipient_count = d.int()?;
        d.leave();
        Ok(Self {
            server_msg_id,
            created_at,
            recipient_count,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MessagesGetEncrypted {
    pub limit: i32,
}

impl TlObject for MessagesGetEncrypted {
    const CTOR: u32 = 0x8ebf4b02;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.int(self.limit);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let limit = d.int()?;
        d.leave();
        Ok(Self {
            limit,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MessagesPersistEncrypted {
    pub records: Vec<MessagesStoredRecord>,
}

impl TlObject for MessagesPersistEncrypted {
    const CTOR: u32 = 0xd1a20002;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        {
            let __v = &self.records;
            e.vector_header(__v.len())?;
            for __x in __v {
                __x.encode(e)?;
            }
        }
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let records = {
            let __n = d.vector_header()?;
            let mut __v = Vec::with_capacity(__n);
            for _ in 0..__n {
                __v.push(MessagesStoredRecord::decode(d)?);
            }
            __v
        };
        d.leave();
        Ok(Self {
            records,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MessagesPersisted {
    pub server_msg_id: String,
    pub created_at: i64,
    pub recipient_count: i32,
}

impl TlObject for MessagesPersisted {
    const CTOR: u32 = 0xd1a20003;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.string(&self.server_msg_id)?;
        e.long(self.created_at);
        e.int(self.recipient_count);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let server_msg_id = d.string()?;
        let created_at = d.long()?;
        let recipient_count = d.int()?;
        d.leave();
        Ok(Self {
            server_msg_id,
            created_at,
            recipient_count,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MessagesSendEncrypted {
    pub client_msg_id: String,
    pub chat_id: i64,
    pub schema: String,
    pub suite: String,
    pub recipients: Vec<MessagesEncryptedRecipient>,
    pub associated_data: Vec<u8>,
    pub forward_info: Option<Vec<u8>>,
    pub reply_to: Option<i64>,
}

impl TlObject for MessagesSendEncrypted {
    const CTOR: u32 = 0x0f7c6b21;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        let mut flags = crate::Flags(0);
        flags = flags.set(0, self.forward_info.is_some());
        flags = flags.set(1, self.reply_to.is_some());
        e.uint(flags.0);
        e.string(&self.client_msg_id)?;
        e.long(self.chat_id);
        e.string(&self.schema)?;
        e.string(&self.suite)?;
        {
            let __v = &self.recipients;
            e.vector_header(__v.len())?;
            for __x in __v {
                __x.encode(e)?;
            }
        }
        e.bytes(&self.associated_data)?;
        if let Some(__v) = &self.forward_info {
            e.bytes(__v)?;
        }
        if let Some(__v) = &self.reply_to {
            e.long(*__v);
        }
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let flags = crate::Flags(d.uint()?);
        let client_msg_id = d.string()?;
        let chat_id = d.long()?;
        let schema = d.string()?;
        let suite = d.string()?;
        let recipients = {
            let __n = d.vector_header()?;
            let mut __v = Vec::with_capacity(__n);
            for _ in 0..__n {
                __v.push(MessagesEncryptedRecipient::decode(d)?);
            }
            __v
        };
        let associated_data = d.bytes()?;
        let forward_info = if flags.has(0) { Some(d.bytes()?) } else { None };
        let reply_to = if flags.has(1) { Some(d.long()?) } else { None };
        d.leave();
        Ok(Self {
            client_msg_id,
            chat_id,
            schema,
            suite,
            recipients,
            associated_data,
            forward_info,
            reply_to,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MessagesStoredRecord {
    pub server_msg_id: String,
    pub client_msg_id: String,
    pub sender_user_id: i64,
    pub sender_device_id: i64,
    pub recipient_user_id: i64,
    pub recipient_device_id: i64,
    pub chat_id: i64,
    pub schema: String,
    pub suite: String,
    pub envelope_type: String,
    pub header: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub associated_data: Vec<u8>,
    pub forward_info: Option<Vec<u8>>,
    pub reply_to: Option<i64>,
    pub message_fingerprint: Vec<u8>,
    pub transparency_proof: Vec<u8>,
    pub created_at: i64,
}

impl TlObject for MessagesStoredRecord {
    const CTOR: u32 = 0xd1a20001;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        let mut flags = crate::Flags(0);
        flags = flags.set(0, self.forward_info.is_some());
        flags = flags.set(1, self.reply_to.is_some());
        e.uint(flags.0);
        e.string(&self.server_msg_id)?;
        e.string(&self.client_msg_id)?;
        e.long(self.sender_user_id);
        e.long(self.sender_device_id);
        e.long(self.recipient_user_id);
        e.long(self.recipient_device_id);
        e.long(self.chat_id);
        e.string(&self.schema)?;
        e.string(&self.suite)?;
        e.string(&self.envelope_type)?;
        e.bytes(&self.header)?;
        e.bytes(&self.ciphertext)?;
        e.bytes(&self.associated_data)?;
        if let Some(__v) = &self.forward_info {
            e.bytes(__v)?;
        }
        if let Some(__v) = &self.reply_to {
            e.long(*__v);
        }
        e.bytes(&self.message_fingerprint)?;
        e.bytes(&self.transparency_proof)?;
        e.long(self.created_at);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let flags = crate::Flags(d.uint()?);
        let server_msg_id = d.string()?;
        let client_msg_id = d.string()?;
        let sender_user_id = d.long()?;
        let sender_device_id = d.long()?;
        let recipient_user_id = d.long()?;
        let recipient_device_id = d.long()?;
        let chat_id = d.long()?;
        let schema = d.string()?;
        let suite = d.string()?;
        let envelope_type = d.string()?;
        let header = d.bytes()?;
        let ciphertext = d.bytes()?;
        let associated_data = d.bytes()?;
        let forward_info = if flags.has(0) { Some(d.bytes()?) } else { None };
        let reply_to = if flags.has(1) { Some(d.long()?) } else { None };
        let message_fingerprint = d.bytes()?;
        let transparency_proof = d.bytes()?;
        let created_at = d.long()?;
        d.leave();
        Ok(Self {
            server_msg_id,
            client_msg_id,
            sender_user_id,
            sender_device_id,
            recipient_user_id,
            recipient_device_id,
            chat_id,
            schema,
            suite,
            envelope_type,
            header,
            ciphertext,
            associated_data,
            forward_info,
            reply_to,
            message_fingerprint,
            transparency_proof,
            created_at,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct OneTimePreKey {
    pub id: i32,
    pub r#pub: Vec<u8>,
}

impl TlObject for OneTimePreKey {
    const CTOR: u32 = 0x6e2f8d11;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.int(self.id);
        e.bytes(&self.r#pub)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let id = d.int()?;
        let r#pub = d.bytes()?;
        d.leave();
        Ok(Self {
            id,
            r#pub,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Ping {
    pub ping_id: i64,
}

impl TlObject for Ping {
    const CTOR: u32 = 0x7abe77ec;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.ping_id);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let ping_id = d.long()?;
        d.leave();
        Ok(Self {
            ping_id,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Pong {
    pub ping_id: i64,
    pub now: i64,
}

impl TlObject for Pong {
    const CTOR: u32 = 0xfebc6767;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.ping_id);
        e.long(self.now);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let ping_id = d.long()?;
        let now = d.long()?;
        d.leave();
        Ok(Self {
            ping_id,
            now,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct RecoveryBundle {
    pub bundle_id: String,
    pub client_ref: String,
    pub schema: String,
    pub suite: String,
    pub opaque_blob: Vec<u8>,
    pub server_share_commitment: Vec<u8>,
    pub metadata: Vec<u8>,
    pub device_transparency_sequence: i64,
    pub device_transparency_entry_hash: Vec<u8>,
    pub updated_at: i64,
}

impl TlObject for RecoveryBundle {
    const CTOR: u32 = 0xa9b3842e;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.string(&self.bundle_id)?;
        e.string(&self.client_ref)?;
        e.string(&self.schema)?;
        e.string(&self.suite)?;
        e.bytes(&self.opaque_blob)?;
        e.bytes(&self.server_share_commitment)?;
        e.bytes(&self.metadata)?;
        e.long(self.device_transparency_sequence);
        e.bytes(&self.device_transparency_entry_hash)?;
        e.long(self.updated_at);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let bundle_id = d.string()?;
        let client_ref = d.string()?;
        let schema = d.string()?;
        let suite = d.string()?;
        let opaque_blob = d.bytes()?;
        let server_share_commitment = d.bytes()?;
        let metadata = d.bytes()?;
        let device_transparency_sequence = d.long()?;
        let device_transparency_entry_hash = d.bytes()?;
        let updated_at = d.long()?;
        d.leave();
        Ok(Self {
            bundle_id,
            client_ref,
            schema,
            suite,
            opaque_blob,
            server_share_commitment,
            metadata,
            device_transparency_sequence,
            device_transparency_entry_hash,
            updated_at,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct RecoveryBundleDeleted {
    pub bundle_id: String,
    pub deleted: bool,
}

impl TlObject for RecoveryBundleDeleted {
    const CTOR: u32 = 0xde850a5f;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.string(&self.bundle_id)?;
        e.bool(self.deleted);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let bundle_id = d.string()?;
        let deleted = d.bool()?;
        d.leave();
        Ok(Self {
            bundle_id,
            deleted,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct RecoveryDeleteBundle {
    pub bundle_id: String,
    pub access_proof_issued_at: i64,
    pub access_proof_nonce: Vec<u8>,
    pub access_proof_signature: Vec<u8>,
}

impl TlObject for RecoveryDeleteBundle {
    const CTOR: u32 = 0x6ccbd710;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.string(&self.bundle_id)?;
        e.long(self.access_proof_issued_at);
        e.bytes(&self.access_proof_nonce)?;
        e.bytes(&self.access_proof_signature)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let bundle_id = d.string()?;
        let access_proof_issued_at = d.long()?;
        let access_proof_nonce = d.bytes()?;
        let access_proof_signature = d.bytes()?;
        d.leave();
        Ok(Self {
            bundle_id,
            access_proof_issued_at,
            access_proof_nonce,
            access_proof_signature,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct RecoveryGetBundle {
    pub access_proof_issued_at: i64,
    pub access_proof_nonce: Vec<u8>,
    pub access_proof_signature: Vec<u8>,
}

impl TlObject for RecoveryGetBundle {
    const CTOR: u32 = 0x58b11483;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.access_proof_issued_at);
        e.bytes(&self.access_proof_nonce)?;
        e.bytes(&self.access_proof_signature)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let access_proof_issued_at = d.long()?;
        let access_proof_nonce = d.bytes()?;
        let access_proof_signature = d.bytes()?;
        d.leave();
        Ok(Self {
            access_proof_issued_at,
            access_proof_nonce,
            access_proof_signature,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct RecoveryPutBundle {
    pub client_ref: String,
    pub schema: String,
    pub suite: String,
    pub opaque_blob: Vec<u8>,
    pub server_share_commitment: Vec<u8>,
    pub metadata: Vec<u8>,
    pub access_proof_issued_at: i64,
    pub access_proof_nonce: Vec<u8>,
    pub access_proof_signature: Vec<u8>,
}

impl TlObject for RecoveryPutBundle {
    const CTOR: u32 = 0xcf3a02ba;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.string(&self.client_ref)?;
        e.string(&self.schema)?;
        e.string(&self.suite)?;
        e.bytes(&self.opaque_blob)?;
        e.bytes(&self.server_share_commitment)?;
        e.bytes(&self.metadata)?;
        e.long(self.access_proof_issued_at);
        e.bytes(&self.access_proof_nonce)?;
        e.bytes(&self.access_proof_signature)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let client_ref = d.string()?;
        let schema = d.string()?;
        let suite = d.string()?;
        let opaque_blob = d.bytes()?;
        let server_share_commitment = d.bytes()?;
        let metadata = d.bytes()?;
        let access_proof_issued_at = d.long()?;
        let access_proof_nonce = d.bytes()?;
        let access_proof_signature = d.bytes()?;
        d.leave();
        Ok(Self {
            client_ref,
            schema,
            suite,
            opaque_blob,
            server_share_commitment,
            metadata,
            access_proof_issued_at,
            access_proof_nonce,
            access_proof_signature,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct RpcResult {
    pub code: i32,
    pub message: String,
}

impl TlObject for RpcResult {
    const CTOR: u32 = 0x38cfdbeb;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.int(self.code);
        e.string(&self.message)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let code = d.int()?;
        let message = d.string()?;
        d.leave();
        Ok(Self {
            code,
            message,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct SenderKeyGroupMembershipContract {
    pub suite: String,
    pub envelope_type: String,
    pub chat_id: i64,
    pub sender_user_id: i64,
    pub sender_device_id: i64,
    pub membership_epoch: i64,
    pub sender_key_id: String,
    pub member_device_count: i32,
    pub member_devices_sha256: String,
}

impl TlObject for SenderKeyGroupMembershipContract {
    const CTOR: u32 = 0xe2ee0004;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.string(&self.suite)?;
        e.string(&self.envelope_type)?;
        e.long(self.chat_id);
        e.long(self.sender_user_id);
        e.long(self.sender_device_id);
        e.long(self.membership_epoch);
        e.string(&self.sender_key_id)?;
        e.int(self.member_device_count);
        e.string(&self.member_devices_sha256)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let suite = d.string()?;
        let envelope_type = d.string()?;
        let chat_id = d.long()?;
        let sender_user_id = d.long()?;
        let sender_device_id = d.long()?;
        let membership_epoch = d.long()?;
        let sender_key_id = d.string()?;
        let member_device_count = d.int()?;
        let member_devices_sha256 = d.string()?;
        d.leave();
        Ok(Self {
            suite,
            envelope_type,
            chat_id,
            sender_user_id,
            sender_device_id,
            membership_epoch,
            sender_key_id,
            member_device_count,
            member_devices_sha256,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct SignalSessionBootstrapContract {
    pub suite: String,
    pub envelope_type: String,
    pub recipient_user_id: i64,
    pub recipient_device_id: i64,
    pub recipient_identity_key_sha256: String,
    pub recipient_signed_pre_key_id: i32,
    pub recipient_signed_pre_key_pub_sha256: String,
    pub recipient_signed_pre_key_sig_sha256: String,
    pub recipient_one_time_pre_key_id: i32,
    pub sender_identity_key: Vec<u8>,
    pub sender_ephemeral_key: Vec<u8>,
}

impl TlObject for SignalSessionBootstrapContract {
    const CTOR: u32 = 0xe2ee0008;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.string(&self.suite)?;
        e.string(&self.envelope_type)?;
        e.long(self.recipient_user_id);
        e.long(self.recipient_device_id);
        e.string(&self.recipient_identity_key_sha256)?;
        e.int(self.recipient_signed_pre_key_id);
        e.string(&self.recipient_signed_pre_key_pub_sha256)?;
        e.string(&self.recipient_signed_pre_key_sig_sha256)?;
        e.int(self.recipient_one_time_pre_key_id);
        e.bytes(&self.sender_identity_key)?;
        e.bytes(&self.sender_ephemeral_key)?;
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let suite = d.string()?;
        let envelope_type = d.string()?;
        let recipient_user_id = d.long()?;
        let recipient_device_id = d.long()?;
        let recipient_identity_key_sha256 = d.string()?;
        let recipient_signed_pre_key_id = d.int()?;
        let recipient_signed_pre_key_pub_sha256 = d.string()?;
        let recipient_signed_pre_key_sig_sha256 = d.string()?;
        let recipient_one_time_pre_key_id = d.int()?;
        let sender_identity_key = d.bytes()?;
        let sender_ephemeral_key = d.bytes()?;
        d.leave();
        Ok(Self {
            suite,
            envelope_type,
            recipient_user_id,
            recipient_device_id,
            recipient_identity_key_sha256,
            recipient_signed_pre_key_id,
            recipient_signed_pre_key_pub_sha256,
            recipient_signed_pre_key_sig_sha256,
            recipient_one_time_pre_key_id,
            sender_identity_key,
            sender_ephemeral_key,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct UpdateNewMessages {
    pub chat_id: i64,
    pub sender_user_id: i64,
    pub pending_count: i32,
}

impl TlObject for UpdateNewMessages {
    const CTOR: u32 = 0x1f6ac3d2;

    fn encode(&self, e: &mut Encoder) -> Result<()> {
        e.ctor(Self::CTOR);
        e.long(self.chat_id);
        e.long(self.sender_user_id);
        e.int(self.pending_count);
        Ok(())
    }

    fn decode(d: &mut Decoder) -> Result<Self> {
        let ctor = d.ctor()?;
        if ctor != Self::CTOR {
            return Err(crate::TlError::UnexpectedCtor { expected: Self::CTOR, got: ctor });
        }
        d.enter()?;
        let chat_id = d.long()?;
        let sender_user_id = d.long()?;
        let pending_count = d.int()?;
        d.leave();
        Ok(Self {
            chat_id,
            sender_user_id,
            pending_count,
        })
    }
}
