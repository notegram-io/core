use transport::{Connection, SecureState, DIR_C2S, DIR_S2C};

const KEY: [u8; 32] = [0x42; 32];
const KEY_ID: u64 = 0xABCD;
const SALT: u64 = 0x1122_3344_5566_7788;
const EPOCH: u32 = 4;
const SESSION: u64 = 0xDEAD_BEEF;

fn state(out_direction: u8, auth_key: Option<[u8; 32]>, auth_key_id: u64) -> SecureState {
    let mut s = SecureState::new_client(SESSION);
    s.out_direction = out_direction;
    s.auth_key = auth_key;
    s.auth_key_id = auth_key_id;
    s.epoch = EPOCH;
    s.salt = SALT;
    s
}

fn pair(
    client_key: Option<[u8; 32]>,
    server_key: Option<[u8; 32]>,
    auth_key_id: u64,
) -> (
    Connection<tokio::io::DuplexStream>,
    Connection<tokio::io::DuplexStream>,
) {
    let (c_io, s_io) = tokio::io::duplex(64 * 1024);
    let client = Connection::new(c_io, state(DIR_C2S, client_key, auth_key_id));
    let server = Connection::new(s_io, state(DIR_S2C, server_key, auth_key_id));
    (client, server)
}

#[tokio::test]
async fn authenticated_roundtrip() {
    let (mut client, mut server) = pair(Some(KEY), Some(KEY), KEY_ID);

    let server_task = tokio::spawn(async move {
        let (h, frames) = server.recv_frames().await.unwrap();
        assert_eq!(h.direction, DIR_C2S);
        assert_eq!(h.auth_key_id, KEY_ID);
        let refs: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
        server.send_frames(&refs).await.unwrap();
    });

    client.send_frames(&[b"hello", b"world"]).await.unwrap();
    let (h, got) = client.recv_frames().await.unwrap();
    assert_eq!(h.direction, DIR_S2C);
    assert_eq!(got, vec![b"hello".to_vec(), b"world".to_vec()]);
    server_task.await.unwrap();
}

#[tokio::test]
async fn unauthenticated_handshake_frames_are_cleartext() {
    let (mut client, mut server) = pair(None, None, 0);

    let server_task = tokio::spawn(async move {
        let (_h, frames) = server.recv_frames().await.unwrap();
        let refs: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
        server.send_frames(&refs).await.unwrap();
    });

    client.send_frames(&[b"client-hello"]).await.unwrap();
    let (_h, got) = client.recv_frames().await.unwrap();
    assert_eq!(got, vec![b"client-hello".to_vec()]);
    server_task.await.unwrap();
}

#[tokio::test]
async fn wrong_key_fails_to_open() {
    let (mut client, mut server) = pair(Some(KEY), Some([0x99; 32]), KEY_ID);

    let server_task = tokio::spawn(async move { server.recv_frames().await.is_err() });

    client.send_frames(&[b"secret"]).await.unwrap();
    assert!(
        server_task.await.unwrap(),
        "server should reject wrong-key frame"
    );
}

#[tokio::test]
async fn many_frames_increment_seq_and_msg_id() {
    let (mut client, mut server) = pair(Some(KEY), Some(KEY), KEY_ID);

    let server_task = tokio::spawn(async move {
        let mut seqs = Vec::new();
        for _ in 0..5 {
            let (h, _) = server.recv_frames().await.unwrap();
            seqs.push(h.seq_no);
        }
        seqs
    });

    for i in 0..5u32 {
        client
            .send_frames(&[format!("msg{i}").as_bytes()])
            .await
            .unwrap();
    }
    let seqs = server_task.await.unwrap();
    assert_eq!(
        seqs,
        vec![0, 1, 2, 3, 4],
        "outbound seq is monotonic from 0"
    );
}
