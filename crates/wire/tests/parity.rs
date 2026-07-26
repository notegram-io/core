use wire::*;

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    assert!(s.len() % 2 == 0, "odd hex len: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn matches_go_vectors() {
    let raw = include_str!("vectors.txt");
    let mut ints = 0;
    let mut frames = 0;

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        match f[0] {
            "int" => {
                let width: u32 = f[1].parse().unwrap();
                let value: u64 = f[2].parse().unwrap();
                let want = unhex(f[3]);
                let mut got = Vec::new();
                match width {
                    16 => append_u16_le(&mut got, value as u16),
                    32 => append_u32_le(&mut got, value as u32),
                    64 => append_u64_le(&mut got, value),
                    w => panic!("bad width {w}"),
                }
                assert_eq!(got, want, "encode int{width} value={value}");

                let back = match width {
                    16 => u16_le(&want) as u64,
                    32 => u32_le(&want) as u64,
                    64 => u64_le(&want),
                    _ => unreachable!(),
                };
                assert_eq!(back, value, "decode int{width}");
                ints += 1;
            }
            "frame" => {
                let payload = unhex(f[1]);
                let want_framed = unhex(f[2]);
                assert_eq!(encode_frame(&payload), want_framed, "encode_frame");
                let mut cur = std::io::Cursor::new(want_framed.clone());
                let got = read_frame(&mut cur, 1 << 20).expect("read_frame");
                assert_eq!(got, payload, "read_frame payload");
                frames += 1;
            }
            other => panic!("unknown record {other}"),
        }
    }
    assert!(
        ints >= 10 && frames >= 3,
        "too few vectors ({ints} ints, {frames} frames)"
    );
}
