use std::collections::BTreeMap;

use crate::Result;

pub trait Backend {
    fn put(&mut self, namespace: &str, key: &[u8], value: &[u8]) -> Result<()>;

    fn get(&self, namespace: &str, key: &[u8]) -> Result<Option<Vec<u8>>>;

    fn delete(&mut self, namespace: &str, key: &[u8]) -> Result<()>;

    fn list(&self, namespace: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>>;
}

#[derive(Default)]
pub struct MemoryBackend {
    data: BTreeMap<String, BTreeMap<Vec<u8>, Vec<u8>>>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        MemoryBackend::default()
    }
}

impl Backend for MemoryBackend {
    fn put(&mut self, namespace: &str, key: &[u8], value: &[u8]) -> Result<()> {
        self.data
            .entry(namespace.to_string())
            .or_default()
            .insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn get(&self, namespace: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.data.get(namespace).and_then(|m| m.get(key)).cloned())
    }

    fn delete(&mut self, namespace: &str, key: &[u8]) -> Result<()> {
        if let Some(m) = self.data.get_mut(namespace) {
            m.remove(key);
        }
        Ok(())
    }

    fn list(&self, namespace: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        Ok(self
            .data
            .get(namespace)
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default())
    }
}
