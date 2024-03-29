use std::{collections::HashMap, sync::Mutex};

use linked_hash_map::LinkedHashMap;
use memmap2::MmapRaw;

use crate::{is_power_of_two, platform::PAGESIZE, Error};

/// Resources limit options for a `Cache`.
///
/// Default value has sensible choices (hopefully) for the system this is built
/// for.
#[derive(Debug, Clone)]
pub struct CacheOptions {
    /// The maximum size of one single mapping, in bytes. Must be a power of two
    /// and bigger than the page size.
    pub max_mapping_size: usize,

    /// The maximum size, in bytes, that is mapped simultaneously for cache.
    /// Must be multiple of the page size.
    pub max_total_mapped: usize,

    /// Maximum number of individual mappings. Linux distributions usually
    /// limits the number of mappings to ~2**16 per process, so maybe half
    /// of that is a good default?
    pub max_mapping_count: u32,
}

impl CacheOptions {
    /// The default cache settings. Considering the maximum addressable amount
    /// of memory by the pointer size of the current platform (capped at 48
    /// bits), the default values are defined as follows:
    ///
    /// Limits a single mapping size to 1/256 of the maximum memory (16 MB for
    /// 32 bits, 1 TB for 64 bits).
    ///
    /// Limits the total mappings to 1/8 of the maximum memory (512 MB for 32
    /// bits, 32 TB for 64 bits).
    ///
    /// Limits the number of mappings to 2**15 = 32768.
    pub const fn default() -> Self {
        // TODO: tune this settings to 32 bits systems.
        const PTR_SIZE: u32 = if usize::BITS > 48 { 48 } else { usize::BITS };

        const MAX_MAPPING_SIZE: usize = 1usize << (PTR_SIZE - 8);
        const MAX_TOTAL_MAPPED: usize = 1usize << (PTR_SIZE - 3);
        const MAX_MAPPING_COUNT: u32 = 1u32 << 15;
        Self {
            max_mapping_size: MAX_MAPPING_SIZE,
            max_total_mapped: MAX_TOTAL_MAPPED,
            max_mapping_count: MAX_MAPPING_COUNT,
        }
    }
}

/// Cache of file mappings shared between many `FileGroup`s. This will control
/// the resource usage of the `FileGroup`s sharing this cache. The idea is that
/// the user will only need one `Cache` per application.
#[derive(Debug)]
pub struct Cache {
    pub(crate) inner: Mutex<CacheImpl>,
}

impl Cache {
    pub fn new(options: CacheOptions) -> Option<Self> {
        // TODO: return an error type instead of a None
        if options.max_mapping_size < *PAGESIZE as usize {
            // `max_mapping_size` is smaller than
            None
        } else if !is_power_of_two(options.max_mapping_size) {
            // `max_mapping_size` is not a power of two
            None
        } else if options.max_total_mapped % *PAGESIZE as usize != 0 {
            // `max_total_mapped` is not multiple of the page size
            None
        } else if options.max_total_mapped < options.max_mapping_size {
            // `max_mapping_size` bigger than `max_total_mapped`
            None
        } else {
            Some(Self {
                inner: Mutex::new(CacheImpl {
                    cache: HashMap::new(),
                    lru_fifo: LinkedHashMap::new(),
                    total_mapped_size: 0,
                    options,
                    identifier_counter: 0,
                }),
            })
        }
    }

    pub fn default() -> Self {
        Self {
            inner: Mutex::new(CacheImpl {
                cache: HashMap::new(),
                lru_fifo: LinkedHashMap::new(),
                total_mapped_size: 0,
                options: CacheOptions::default(),
                identifier_counter: 0,
            }),
        }
    }

    pub fn get_options(&self) -> CacheOptions {
        // TODO: it is a little silly to have to lock the mutex here just to get
        // the options. When refactoring to have less contention, fix this.
        self.inner.lock().unwrap().get_options().clone()
    }
}

#[derive(Debug)]
pub(crate) struct CacheImpl {
    /// Stores the cached entries.
    ///
    /// Key is unique id of the FileGroup, and the global position inside it.
    ///
    /// Value is the mapping, and the number of users.
    ///
    /// TODO: maybe use an atomic value as the counter to reduce contention, so
    /// this can be placed in a RwLock instead of wrapping the entire struct in
    /// a mutex, and cache hits will only need a read lock.
    cache: HashMap<(u64, u64), (MmapRaw, usize)>,
    options: CacheOptions,
    lru_fifo: LinkedHashMap<(u64, u64), ()>,
    total_mapped_size: usize,

    /// Every FileGroup created from this Cache will have a global unique
    /// identifier, that it will use as part of the key for queries in the
    /// cache. This counter provides the keys.
    identifier_counter: u64,
}

impl CacheImpl {
    /// Gets an element from cache or create it, and increment its reference
    /// counter.
    ///
    /// The returned pointed element is cached and guaranteed to exist until a
    /// corresponding `put_dec` is issued to the same group_id and offset.
    pub(crate) fn get_inc(
        &mut self,
        group_id: u64,
        offset: u64,
        creator: impl FnOnce() -> Result<MmapRaw, Error>,
    ) -> Result<*const u8, Error> {
        match self.cache.entry((group_id, offset)) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                // Remove entry from the LRU fifo, because it is now in use and
                // can not be dropped.
                self.lru_fifo.remove(entry.key());

                let val = entry.get_mut();
                val.1 += 1;

                Ok(val.0.as_ptr())
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                let mapping = &entry.insert((creator()?, 1)).0;

                // Count the total mapped as a multiple of full pages.
                assert!(mapping.len() <= self.options.max_mapping_size);
                self.total_mapped_size += round_to_whole_pages(mapping.len());

                // Create the return value here so that we "unborrow" self, and
                // maybe_drop_cached() can be called.
                let ret = mapping.as_ptr();

                self.maybe_drop_cached();

                Ok(ret)
            }
        }
    }

    /// Decrements the reference counter of a given cached object, or panics if
    /// it is already zero. After the a number of `put_dec()` calls
    /// corresponding to the number of `get_inc()` calls to the same key, it
    /// is no longer safe to dereference the pointer as the object might have
    /// been destroyed.
    pub(crate) fn put_dec(&mut self, group_id: u64, offset: u64) {
        let key = (group_id, offset);
        let counter = &mut self.cache.get_mut(&key).unwrap().1;
        assert!(*counter > 0);
        *counter -= 1;
        if *counter == 0 {
            // No more users, add it to the LRU fifo.
            self.lru_fifo.insert(key, ());
        }
    }

    pub(crate) fn get_options(&self) -> &CacheOptions {
        &self.options
    }

    pub(crate) fn get_unique_id(&mut self) -> u64 {
        let id = self.identifier_counter;
        self.identifier_counter += 1;
        id
    }

    /// Frees all not in-use cache entries of a FileGroup.
    pub fn remove_file_group(&mut self, group_id: u64) {
        for e in self.lru_fifo.entries() {
            if e.key().0 == group_id {
                assert_eq!(self.cache.remove(e.key()).unwrap().1, 0);
                e.remove();
            }
        }
    }

    /// Drops the least recently used (LRU) elements until cache is within
    /// configured limits.
    fn maybe_drop_cached(&mut self) {
        while self.total_mapped_size > self.options.max_total_mapped
            || self.cache.len() > self.options.max_mapping_count as usize
        {
            match self.lru_fifo.pop_front() {
                Some((to_be_removed, _)) => {
                    let (removed, users) = self.cache.remove(&to_be_removed).unwrap();
                    assert_eq!(users, 0);
                    self.total_mapped_size -= round_to_whole_pages(removed.len());
                }
                None => {
                    // It is unlikely that the maximum limits have been reached,
                    // but there are no entries to be dropped. But it is not
                    // necessarily a bug: it is possible that every entry are in
                    // use right now, so there is nothing else to do.
                    break;
                }
            }
        }
    }
}

fn round_to_whole_pages(size: usize) -> usize {
    let pg_max = (*PAGESIZE - 1) as usize;
    (size + pg_max) & !pg_max
}
