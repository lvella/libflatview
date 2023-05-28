/// Cache of file mappings shared between many `FileGroup`s. This will control
/// the resource usage of the `FileGroup`s sharing this cache. The idea is that
/// the user will only need one `Cache` per application.
pub struct Cache {}

/// Resources limit options for the a `Cache`.
///
/// Default value has sensible choices (hopefully) for the system this is built
/// for.
#[derive(Debug, Clone)]
pub struct CacheOptions {
    /// The maximum size of one single mapping, in bytes. Must be multiple of
    /// the page size.
    pub max_mapping_size: usize,

    /// The maximum size, in bytes, that is mapped simultaneously for cache.
    /// Also must be multiple of the page size.
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

pub struct CacheImpl {}
