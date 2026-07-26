use rusqlite::{params, Connection, OptionalExtension};

use crate::backend::Backend;
use crate::{Result, StoreError};

pub struct SqliteBackend {
    conn: Connection,
}

impl SqliteBackend {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path).map_err(backend_err)?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(backend_err)?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(backend_err)?;
        conn.pragma_update(None, "foreign_keys", true)
            .map_err(backend_err)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS records (
                namespace TEXT NOT NULL,
                key       BLOB NOT NULL,
                value     BLOB NOT NULL,
                PRIMARY KEY (namespace, key)
            ) WITHOUT ROWID;",
        )
        .map_err(backend_err)?;
        Ok(SqliteBackend { conn })
    }
}

impl Backend for SqliteBackend {
    fn put(&mut self, namespace: &str, key: &[u8], value: &[u8]) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO records (namespace, key, value) VALUES (?1, ?2, ?3)
                 ON CONFLICT(namespace, key) DO UPDATE SET value = excluded.value",
                params![namespace, key, value],
            )
            .map_err(backend_err)?;
        Ok(())
    }

    fn get(&self, namespace: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.conn
            .query_row(
                "SELECT value FROM records WHERE namespace = ?1 AND key = ?2",
                params![namespace, key],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(backend_err)
    }

    fn delete(&mut self, namespace: &str, key: &[u8]) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM records WHERE namespace = ?1 AND key = ?2",
                params![namespace, key],
            )
            .map_err(backend_err)?;
        Ok(())
    }

    fn list(&self, namespace: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT key, value FROM records WHERE namespace = ?1 ORDER BY key ASC")
            .map_err(backend_err)?;
        let rows = stmt
            .query_map(params![namespace], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(backend_err)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(backend_err)?);
        }
        Ok(out)
    }
}

fn backend_err(e: rusqlite::Error) -> StoreError {
    StoreError::Backend(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::MASTER_KEY_LEN;
    use crate::{Namespace, SecureStore};

    #[test]
    fn persists_sealed_records_across_reopen_of_the_same_connection() {
        let backend = SqliteBackend::open_in_memory().unwrap();
        let mut store = SecureStore::open(&[5u8; MASTER_KEY_LEN], backend).unwrap();
        store
            .put(Namespace::Session, b"peer-1", b"ratchet-state")
            .unwrap();
        assert_eq!(
            store.get(Namespace::Session, b"peer-1").unwrap().as_deref(),
            Some(b"ratchet-state".as_ref())
        );

        let raw = store
            .backend()
            .get(Namespace::Session.label(), b"peer-1")
            .unwrap()
            .unwrap();
        assert!(!raw
            .windows(b"ratchet-state".len())
            .any(|w| w == b"ratchet-state"));
    }

    #[test]
    fn list_is_sorted_and_delete_removes() {
        let backend = SqliteBackend::open_in_memory().unwrap();
        let mut store = SecureStore::open(&[6u8; MASTER_KEY_LEN], backend).unwrap();
        store.put(Namespace::Outbox, b"b", b"2").unwrap();
        store.put(Namespace::Outbox, b"a", b"1").unwrap();
        assert_eq!(
            store.list(Namespace::Outbox).unwrap(),
            vec![
                (b"a".to_vec(), b"1".to_vec()),
                (b"b".to_vec(), b"2".to_vec())
            ]
        );
        store.delete(Namespace::Outbox, b"a").unwrap();
        assert_eq!(
            store.list(Namespace::Outbox).unwrap(),
            vec![(b"b".to_vec(), b"2".to_vec())]
        );
    }
}
