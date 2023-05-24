/// Cache of file mappings shared between many `FileGroup`s. This will control
/// the resource usage of the `FileGroup`s sharing this cache. The idea is that
/// the user will only need one `Cache` per application.
pub struct Cache {}

/// Resources limit options for the a `Cache`.
///
/// Default value has sensible choices (hopefully) for the system this is built
/// for.
pub struct CacheOptions {
    /// The maximum size of one single mapping, in bytes. Must be multiple of
    /// the page size.
    max_mapping_size: usize,

    /// The maximum size, in bytes, that is mapped simultaneously for cache.
    /// Also must be multiple of the page size.
    max_total_mapped: usize,

    /// Maximum number of individual mappings. Linux distributions usually
    /// limits the number of mappings to ~2**16 per process, so maybe half
    /// of that is a good default?
    max_mapping_count: u32,
}

struct CacheImpl {}
