use std::collections::HashMap;

use kt::{parse_and_verify_membership, verify_str_witnesses};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn membership_proofs_verify_against_directory() {
    let raw = include_str!("membership_vectors.txt");
    let mut sign_pub = Vec::new();
    let mut trusted: HashMap<String, Vec<u8>> = HashMap::new();
    let mut min = 0usize;
    let mut checked = 0;

    for line in raw.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.is_empty() {
            continue;
        }
        match f[0] {
            "sign_pub" => sign_pub = unhex(f[1]),
            "witness" => {
                trusted.insert(f[1].to_string(), unhex(f[2]));
            }
            "min" => min = f[1].parse().unwrap(),
            "proof" => {
                let normalized = f[1];
                let user_id: i64 = f[2].parse().unwrap();
                let blob = unhex(f[3]);

                let (entry, str) = parse_and_verify_membership(&blob)
                    .unwrap_or_else(|| panic!("proof for {normalized} must verify"));
                assert_eq!(entry.normalized, normalized);
                assert_eq!(entry.user_id, user_id, "userID binding for {normalized}");
                assert_eq!(str.public, sign_pub, "STR signed by the directory key");
                assert_eq!(str.witnesses.len(), 2);

                assert!(
                    verify_str_witnesses(&str, &trusted, min),
                    "witness threshold for {normalized}"
                );

                let untrusted: HashMap<String, Vec<u8>> = HashMap::new();
                assert!(!verify_str_witnesses(&str, &untrusted, min));

                for &pos in &[0usize, blob.len() / 2, blob.len() - 1] {
                    let mut bad = blob.clone();
                    bad[pos] ^= 0x01;
                    assert!(
                        parse_and_verify_membership(&bad).is_none(),
                        "tamper at {pos} must fail for {normalized}"
                    );
                }
                checked += 1;
            }
            _ => {}
        }
    }
    assert!(
        checked >= 3,
        "expected >= 3 membership proofs, got {checked}"
    );
}
