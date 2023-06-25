/// Caches at most one value.
pub struct SingleCache<K: Eq, V>(Option<(K, V)>);

impl<K: Eq, V> SingleCache<K, V> {
    pub fn new() -> Self {
        SingleCache(None)
    }

    pub fn get_mut<'a, E>(
        &'a mut self,
        key: K,
        constructor: impl FnOnce(&K) -> Result<V, E>,
    ) -> Result<&'a mut V, E> {
        if let Some((k, _)) = self.0.as_ref() {
            if *k != key {
                self.0 = None;
            }
        }

        if let None = self.0 {
            let v = constructor(&key)?;
            self.0 = Some((key, v));
        }

        Ok(&mut self.0.as_mut().unwrap().1)
    }
}
