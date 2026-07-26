use std::collections::HashMap;

use crypto::{ed25519_public, ed25519_sign, x25519_dh, x25519_generate, x25519_public};
use proto::handshake::{
    auth_key_id, compute_finished, derive_auth_key, transcript_bytes, verify_server_params_sig,
    ClientHandshake, Transcript,
};
use tl::generated::{AuthHandshakeOk, AuthHandshakeParams};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn arr32(s: &str) -> [u8; 32] {
    unhex(s).try_into().unwrap()
}

fn vectors() -> HashMap<String, String> {
    include_str!("handshake_vectors.txt")
        .lines()
        .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let (k, v) = l.split_once(' ').unwrap();
            (k.to_string(), v.to_string())
        })
        .collect()
}

#[test]
fn derivations_match_session_gateway() {
    let v = vectors();
    let h = |k: &str| -> Vec<u8> { unhex(&v[k]) };
    let server_pub_key_id: i64 = v["server_pub_key_id"].parse().unwrap();

    assert_eq!(
        x25519_public(&arr32(&v["client_eph_priv"])).to_vec(),
        h("client_eph_pub")
    );
    assert_eq!(
        x25519_public(&arr32(&v["server_eph_priv"])).to_vec(),
        h("server_eph_pub")
    );
    let shared = x25519_dh(&arr32(&v["client_eph_priv"]), &arr32(&v["server_eph_pub"]));
    assert_eq!(shared.to_vec(), h("shared_secret"));
    assert_eq!(
        x25519_dh(&arr32(&v["server_eph_priv"]), &arr32(&v["client_eph_pub"])),
        shared,
        "DH is symmetric"
    );

    let t = Transcript {
        tmp_token: h("tmp_token"),
        client_nonce: h("client_nonce"),
        server_nonce: h("server_nonce"),
        client_eph_pub: h("client_eph_pub"),
        server_eph_pub: h("server_eph_pub"),
        epoch: v["epoch"].parse().unwrap(),
        session_id: v["session_id"].parse().unwrap(),
        salt: v["salt"].parse().unwrap(),
    };

    let auth_key = derive_auth_key(&shared, &t, server_pub_key_id);
    assert_eq!(auth_key.to_vec(), h("auth_key"), "auth_key");
    assert_eq!(
        auth_key_id(&auth_key),
        v["auth_key_id"].parse::<u64>().unwrap(),
        "auth_key_id"
    );
    assert_eq!(
        compute_finished(&auth_key, "client-finished", &t, server_pub_key_id).to_vec(),
        h("client_finished"),
    );
    assert_eq!(
        compute_finished(&auth_key, "server-finished", &t, server_pub_key_id).to_vec(),
        h("server_finished"),
    );

    let sig: [u8; 64] = h("server_params_sig").try_into().unwrap();
    assert!(
        verify_server_params_sig(&arr32(&v["ed25519_pub"]), &t, server_pub_key_id, &sig),
        "server params signature must verify"
    );
}

struct CounterRng(u64);
impl rand_core::RngCore for CounterRng {
    fn next_u32(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 32) as u32
    }
    fn next_u64(&mut self) -> u64 {
        ((self.next_u32() as u64) << 32) | self.next_u32() as u64
    }
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        for chunk in dst.chunks_mut(4) {
            let b = self.next_u32().to_le_bytes();
            chunk.copy_from_slice(&b[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dst);
        Ok(())
    }
}
impl rand_core::CryptoRng for CounterRng {}

#[test]
fn full_client_server_roundtrip() {
    let mut rng = CounterRng(0xC0FFEE);
    let server_seed = [0x77u8; 32];
    let server_ed_pub = ed25519_public(&server_seed);
    let server_pub_key_id: i64 = 5;
    let (server_eph_priv, server_eph_pub) = x25519_generate(&mut rng);

    let (client, begin) =
        ClientHandshake::begin(b"tmp".to_vec(), b"info".to_vec(), 0xABCDEF, &mut rng);

    let client_eph_pub: [u8; 32] = begin.client_eph_pub.clone().try_into().unwrap();
    let t = Transcript {
        tmp_token: begin.tmp_token.clone(),
        client_nonce: begin.client_nonce.clone(),
        server_nonce: b"server-nonce".to_vec(),
        client_eph_pub: client_eph_pub.to_vec(),
        server_eph_pub: server_eph_pub.to_vec(),
        epoch: 11,
        session_id: 0xABCDEF,
        salt: 0x0102_0304_0506_0708,
    };
    let sig = ed25519_sign(
        &server_seed,
        &transcript_bytes("session-gateway/server-params/v2", &t, server_pub_key_id),
    );
    let params = AuthHandshakeParams {
        server_nonce: t.server_nonce.clone(),
        server_eph_pub: server_eph_pub.to_vec(),
        server_pub_key_id,
        sig: sig.to_vec(),
        salt: t.salt,
        epoch: t.epoch as i32,
        expires_in: 3600,
    };

    let (finish, finishing) = client
        .on_params(&params, &server_ed_pub)
        .expect("on_params");

    let server_shared = x25519_dh(&server_eph_priv, &client_eph_pub);
    let server_auth_key = derive_auth_key(&server_shared, &t, server_pub_key_id);
    assert_eq!(
        finish.client_finished,
        compute_finished(&server_auth_key, "client-finished", &t, server_pub_key_id).to_vec(),
        "server validates the client finished"
    );
    let ok = AuthHandshakeOk {
        auth_key_id: auth_key_id(&server_auth_key),
        epoch: t.epoch as i32,
        server_finished: compute_finished(
            &server_auth_key,
            "server-finished",
            &t,
            server_pub_key_id,
        )
        .to_vec(),
        expires_in: 3600,
    };

    let established = finishing.on_ok(&ok).expect("on_ok");
    assert_eq!(
        established.auth_key, server_auth_key,
        "both sides derive the same key"
    );
    assert_eq!(established.auth_key_id, ok.auth_key_id);
    assert_eq!(established.epoch, 11);
    assert_eq!(established.session_id, 0xABCDEF);
}
