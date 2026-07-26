use std::collections::HashMap;

use tl::generated::*;
use tl::{decode_from, encode_to_vec, Limits, TlObject};

fn vectors() -> HashMap<String, String> {
    include_str!("messages.txt")
        .lines()
        .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            assert_eq!(f[0], "msg");
            (f[1].to_string(), f[2].to_string())
        })
        .collect()
}

fn tohex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn check<T: TlObject + PartialEq + std::fmt::Debug>(
    vecs: &HashMap<String, String>,
    name: &str,
    value: T,
) {
    let want = vecs
        .get(name)
        .unwrap_or_else(|| panic!("no vector for {name}"));
    let got = encode_to_vec(&value).unwrap();
    assert_eq!(&tohex(&got), want, "encode {name}");

    let bytes = (0..want.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&want[i..i + 2], 16).unwrap())
        .collect::<Vec<_>>();
    let decoded: T = decode_from(&bytes, Limits::default()).unwrap();
    assert_eq!(decoded, value, "decode {name}");
    assert_eq!(
        tohex(&encode_to_vec(&decoded).unwrap()),
        *want,
        "reencode {name}"
    );
}

#[test]
fn messages_match_go_proto() {
    let v = vectors();

    check(
        &v,
        "Pong",
        Pong {
            ping_id: 7,
            now: 42,
        },
    );

    check(
        &v,
        "MessagesPersisted",
        MessagesPersisted {
            server_msg_id: "abc".into(),
            created_at: 1000,
            recipient_count: 2,
        },
    );

    check(
        &v,
        "MessagesPersistEncrypted",
        MessagesPersistEncrypted {
            records: vec![MessagesStoredRecord {
                server_msg_id: "m1".into(),
                client_msg_id: "c1".into(),
                sender_user_id: 7,
                sender_device_id: 1,
                recipient_user_id: 9,
                recipient_device_id: 2,
                chat_id: 100,
                schema: "s".into(),
                suite: "x".into(),
                envelope_type: "msg".into(),
                header: b"hdr".to_vec(),
                ciphertext: b"ct".to_vec(),
                associated_data: b"ad".to_vec(),
                forward_info: Some(vec![0xaa, 0xbb]),
                reply_to: Some(-5),
                message_fingerprint: b"fp".to_vec(),
                transparency_proof: b"proof".to_vec(),
                created_at: 1_700_000_000_000,
            }],
        },
    );
}
