use tl::{Decoder, Encoder, Limits};

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn tohex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

#[test]
fn matches_go_codec() {
    let raw = include_str!("vectors.txt");
    let mut count = 0;

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        let kind = f[0];
        let want = f[f.len() - 1];

        let mut e = Encoder::new();
        match kind {
            "int" => e.int(f[1].parse().unwrap()),
            "long" => e.long(f[1].parse().unwrap()),
            "uint" => e.uint(f[1].parse().unwrap()),
            "ulong" => e.ulong(f[1].parse().unwrap()),
            "bool" => e.bool(f[1] == "true"),
            "bytes" => e.bytes(&unhex(f[1])).unwrap(),
            "string" => e.string(&String::from_utf8(unhex(f[1])).unwrap()).unwrap(),
            "vector_int" => {
                let vals = parse_ints(f[1]);
                e.vector_header(vals.len()).unwrap();
                for v in &vals {
                    e.int(*v);
                }
            }
            other => panic!("unknown record kind {other}"),
        }
        let got = e.into_bytes();
        assert_eq!(
            tohex(&got),
            want,
            "encode {kind} {}",
            f.get(1).unwrap_or(&"")
        );

        decode_roundtrip(kind, f[1], &got);
        count += 1;
    }
    assert!(count >= 20, "too few vectors ({count})");
}

fn decode_roundtrip(kind: &str, arg: &str, bytes: &[u8]) {
    let mut d = Decoder::new(bytes, Limits::default()).unwrap();
    match kind {
        "int" => assert_eq!(d.int().unwrap(), arg.parse::<i32>().unwrap()),
        "long" => assert_eq!(d.long().unwrap(), arg.parse::<i64>().unwrap()),
        "uint" => assert_eq!(d.uint().unwrap(), arg.parse::<u32>().unwrap()),
        "ulong" => assert_eq!(d.ulong().unwrap(), arg.parse::<u64>().unwrap()),
        "bool" => assert_eq!(d.bool().unwrap(), arg == "true"),
        "bytes" => assert_eq!(d.bytes().unwrap(), unhex(arg)),
        "string" => assert_eq!(d.string().unwrap().as_bytes(), unhex(arg).as_slice()),
        "vector_int" => {
            let vals = parse_ints(arg);
            assert_eq!(d.vector_header().unwrap(), vals.len());
            for v in &vals {
                assert_eq!(d.int().unwrap(), *v);
            }
        }
        _ => unreachable!(),
    }
    assert_eq!(d.remaining(), 0, "trailing bytes after decode of {kind}");
}

fn parse_ints(s: &str) -> Vec<i32> {
    if s == "-" {
        return Vec::new();
    }
    s.split(',').map(|p| p.parse().unwrap()).collect()
}
