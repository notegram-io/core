use e2ee::{
    build_associated_data_v1, build_envelope_header_v2, build_envelope_header_v3,
    build_envelope_header_v4, AssociatedDataInput, EnvelopeHeaderInput, SenderKeyMemberDevice,
    SenderKeyMembershipInput, SignalBootstrapInput,
};
use serde_json::Value;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn tohex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn associated_data_matches_server() {
    let raw = include_str!("binding_vectors.txt");
    let mut count = 0;
    for line in raw.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(line).expect("vector line is json");
        let s = |k: &str| v[k].as_str().unwrap().to_string();
        let i = |k: &str| v[k].as_i64().unwrap();

        let input = AssociatedDataInput {
            schema: s("schema"),
            suite: s("suite"),
            crypto_policy_profile: s("crypto_policy_profile"),
            crypto_policy_version: i("crypto_policy_version"),
            crypto_policy_sha256: s("crypto_policy_sha256"),
            sender_user_id: i("sender_user_id"),
            sender_device_id: i("sender_device_id"),
            chat_id: i("chat_id"),
            client_msg_id: s("client_msg_id"),
            forward_info: unhex(v["forward_info_hex"].as_str().unwrap()),
            reply_to: v["reply_to"].as_i64(),
        };

        let got = build_associated_data_v1(&input);
        assert_eq!(
            tohex(&got),
            v["expected_hex"].as_str().unwrap(),
            "associated data for client_msg_id={}",
            input.client_msg_id
        );
        count += 1;
    }
    assert!(count >= 2, "expected at least 2 vectors, got {count}");
}

#[test]
fn envelope_headers_match_server() {
    let raw = include_str!("header_vectors.txt");
    let mut kinds = Vec::new();
    for line in raw.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(line).expect("vector line is json");
        let s = |k: &str| v[k].as_str().unwrap().to_string();
        let i = |k: &str| v[k].as_i64().unwrap();

        let ad_bytes = unhex(v["associated_data_hex"].as_str().unwrap());
        let ct_bytes = unhex(v["ciphertext_hex"].as_str().unwrap());
        let nonce = unhex(v["message_nonce_hex"].as_str().unwrap());

        let header_input = EnvelopeHeaderInput {
            ad: AssociatedDataInput {
                schema: s("schema"),
                suite: s("suite"),
                crypto_policy_profile: s("crypto_policy_profile"),
                crypto_policy_version: i("crypto_policy_version"),
                crypto_policy_sha256: s("crypto_policy_sha256"),
                sender_user_id: i("sender_user_id"),
                sender_device_id: i("sender_device_id"),
                chat_id: i("chat_id"),
                client_msg_id: s("client_msg_id"),
                forward_info: Vec::new(),
                reply_to: None,
            },
            recipient_user_id: i("recipient_user_id"),
            recipient_device_id: i("recipient_device_id"),
            envelope_type: s("envelope_type"),
        };

        let kind = s("kind");
        let got = match kind.as_str() {
            "v2" => build_envelope_header_v2(&header_input, &ad_bytes, &ct_bytes, &nonce),
            "v3" => {
                let b = &v["bootstrap"];
                let bs = |k: &str| b[k].as_str().unwrap().to_string();
                let bi = |k: &str| b[k].as_i64().unwrap();
                let bootstrap = SignalBootstrapInput {
                    suite: bs("suite"),
                    envelope_type: bs("envelope_type"),
                    recipient_user_id: bi("recipient_user_id"),
                    recipient_device_id: bi("recipient_device_id"),
                    recipient_identity_key: unhex(
                        b["recipient_identity_key_hex"].as_str().unwrap(),
                    ),
                    recipient_signed_pre_key_id: bi("recipient_signed_pre_key_id") as i32,
                    recipient_signed_pre_key_pub: unhex(
                        b["recipient_signed_pre_key_pub_hex"].as_str().unwrap(),
                    ),
                    recipient_signed_pre_key_sig: unhex(
                        b["recipient_signed_pre_key_sig_hex"].as_str().unwrap(),
                    ),
                    recipient_one_time_pre_key_id: bi("recipient_one_time_pre_key_id") as i32,
                    sender_identity_key: unhex(b["sender_identity_key_hex"].as_str().unwrap()),
                    sender_ephemeral_key: unhex(b["sender_ephemeral_key_hex"].as_str().unwrap()),
                };
                build_envelope_header_v3(&header_input, &ad_bytes, &ct_bytes, &nonce, &bootstrap)
            }
            "v4" => {
                let m = &v["membership"];
                let ms = |k: &str| m[k].as_str().unwrap().to_string();
                let mi = |k: &str| m[k].as_i64().unwrap();
                let member_devices = m["member_devices"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|d| SenderKeyMemberDevice {
                        user_id: d["user_id"].as_i64().unwrap(),
                        device_id: d["device_id"].as_i64().unwrap(),
                    })
                    .collect();
                let membership = SenderKeyMembershipInput {
                    suite: ms("suite"),
                    envelope_type: ms("envelope_type"),
                    chat_id: mi("chat_id"),
                    sender_user_id: mi("sender_user_id"),
                    sender_device_id: mi("sender_device_id"),
                    membership_epoch: mi("membership_epoch"),
                    sender_key_id: ms("sender_key_id"),
                    member_devices,
                };
                build_envelope_header_v4(&header_input, &ad_bytes, &ct_bytes, &nonce, &membership)
            }
            other => panic!("unknown header kind {other}"),
        };

        assert_eq!(
            tohex(&got),
            v["expected_hex"].as_str().unwrap(),
            "envelope header kind={kind} client_msg_id={}",
            header_input.ad.client_msg_id
        );
        kinds.push(kind);
    }
    assert!(
        kinds.iter().any(|k| k == "v2")
            && kinds.iter().any(|k| k == "v3")
            && kinds.iter().any(|k| k == "v4"),
        "expected v2, v3, and v4 header vectors, got {kinds:?}"
    );
}
