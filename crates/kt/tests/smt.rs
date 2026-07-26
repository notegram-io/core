use kt::smt;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn arr32(s: &str) -> [u8; 32] {
    unhex(s).try_into().unwrap()
}

#[test]
fn proofs_verify_against_go_root() {
    let raw = include_str!("smt_vectors.txt");
    let mut root = [0u8; 32];
    let mut proofs = 0;
    let mut present_seen = false;
    let mut absent_seen = false;

    for line in raw.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        match f[0] {
            "root" => root = arr32(f[1]),
            "key" => assert_eq!(smt::key(f[1]), arr32(f[2]), "key derivation for {}", f[1]),
            "proof" => {
                let name = f[1];
                let key = arr32(f[2]);
                let present = f[3] == "1";
                let proof = smt::parse(&unhex(f[4])).expect("parse proof");

                assert_eq!(proof.present, present, "present flag for {name}");
                assert!(
                    smt::verify(&root, &key, &proof),
                    "proof for {name} must verify"
                );

                assert_eq!(smt::serialize(&proof), unhex(f[4]), "serialize {name}");

                let mut other = key;
                other[0] ^= 0xFF;
                assert!(
                    !smt::verify(&root, &other, &proof),
                    "proof must bind to its key"
                );

                if present {
                    present_seen = true;
                } else {
                    absent_seen = true;
                }
                proofs += 1;
            }
            _ => {}
        }
    }
    assert!(
        proofs >= 4 && present_seen && absent_seen,
        "need present and absent proofs"
    );

    let mut bad_root = root;
    bad_root[0] ^= 0x01;
    for line in raw.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f[0] == "proof" {
            let key = arr32(f[2]);
            let proof = smt::parse(&unhex(f[4])).unwrap();
            assert!(
                !smt::verify(&bad_root, &key, &proof),
                "proof must not verify under a wrong root"
            );
        }
    }
}
