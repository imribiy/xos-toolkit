use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct CiMap<V> {
    inner: HashMap<String, (String, V)>,
}

impl<V> Default for CiMap<V> {
    fn default() -> Self {
        CiMap {
            inner: HashMap::new(),
        }
    }
}

impl<V> CiMap<V> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: &str, value: V) {
        self.inner
            .insert(key.to_lowercase(), (key.to_string(), value));
    }

    pub fn get(&self, key: &str) -> Option<&V> {
        self.inner.get(&key.to_lowercase()).map(|(_, v)| v)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.inner.contains_key(&key.to_lowercase())
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &V)> {
        self.inner.values().map(|(k, v)| (k, v))
    }

    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.inner.values().map(|(k, _)| k)
    }
}
