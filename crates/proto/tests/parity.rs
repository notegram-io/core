use proto::{derive_msg_key, open_frame, seal_frame, SealParams};

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn tohex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn key32(s: &str) -> [u8; 32] {
    let v = unhex(s);
    let mut k = [0u8; 32];
    k.copy_from_slice(&v);
    k
}

#[test]
fn matches_go_transport() {
    let raw = include_str!("secure_vectors.txt");
    let (mut derives, mut frames) = (0, 0);

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        match f[0] {
            "derive" => {
                let got = derive_msg_key(
                    &key32(f[1]),
                    f[2].parse().unwrap(),
                    f[3].parse().unwrap(),
                    f[4].parse().unwrap(),
                    f[5].parse().unwrap(),
                );
                assert_eq!(tohex(&got), f[6], "derive_msg_key");
                derives += 1;
            }

            "frame" => {
                let key = (f[1] != "-").then(|| key32(f[1]));
                let salt: u64 = f[2].parse().unwrap();
                let auth_key_id: u64 = f[6].parse().unwrap();
                let container = unhex(f[9]);
                let want = f[10];

                let params = SealParams {
                    auth_key: key.as_ref(),
                    salt,
                    epoch: f[3].parse().unwrap(),
                    direction: f[4].parse().unwrap(),
                    session_id: f[5].parse().unwrap(),
                    auth_key_id,
                    seq_no: f[7].parse().unwrap(),
                    msg_id: f[8].parse().unwrap(),
                };

                let sealed = seal_frame(&params, &container).unwrap();
                assert_eq!(tohex(&sealed), want, "seal_frame");

                let (header, recovered) = open_frame(&sealed, key.as_ref(), salt).unwrap();
                assert_eq!(header.auth_key_id, auth_key_id, "header auth_key_id");
                assert_eq!(recovered, container, "open_frame container");
                frames += 1;
            }
            other => panic!("unknown record {other}"),
        }
    }
    assert!(
        derives >= 3 && frames >= 2,
        "too few vectors ({derives}, {frames})"
    );
}
