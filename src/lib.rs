pub mod cache;
mod path_resolver;
mod platform;
mod single_cache;

use cache::Cache;
use memmap2::MmapOptions;
use platform::preallocate_file;
use std::{
    cmp::min,
    fs::{create_dir_all, OpenOptions},
    io::{ErrorKind, IoSlice, IoSliceMut},
    iter::FusedIterator,
    ops::RangeBounds,
    path::{Path, PathBuf},
    ptr,
    sync::Arc,
};

use crate::single_cache::SingleCache;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("system error when accessing a file")]
    IOError(#[from] std::io::Error),
    #[error("file path provided is empty")]
    EmptyPath,
    #[error("a write was attempted on read-only mode")]
    ReadOnlyMode,
    #[error("the range requested is invalid")]
    InvalidRange,
    #[error("file is smaller than expected size")]
    FileTooSmall,
}

/// The operation mode of a `FileGroup`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Files are opened and mapped as read-only.
    ReadOnly,
    /// Files are opened and mapped in read and write mode.
    ///
    /// If `reserve` is set, all non-allocated blocks on sparse files will be
    /// allocated before a mapping is returned to the user. This is recommended,
    /// because if the application tries to write to an unallocated block, but
    /// it can't be allocated because the storage is full, your application will
    /// be signaled with SIGBUS on POSIX and with Structured Error Handling on
    /// Windows.
    ReadWrite { reserve: bool },
}

/// A sequence of files with known sizes grouped together as a single 64-bit
/// addressable byte array.
///
/// Maybe this should go without saying, but in write mode, the object assumes
/// it is the sole writer of the file. This is obvious, of course, as you always
/// have a race condition when two threads/processes writes to the same file
/// without synchronization between them.
#[derive(Debug)]
pub struct FileGroup {
    /// Cache shared among other `FileGroup` storing actual file mappings. It
    /// has to be shared if we want to control the amount of resources used
    /// across all the file groups sharing it.
    cache: Arc<Cache>,

    /// Unique identifier inside the cache.
    unique_id: u64,

    /// Tells if this is in read-write or read-only mode.
    operation_mode: Mode,

    /// The path and size of of every file whose requested size was greater than
    /// zero.
    paths_and_sizes: Vec<(PathBuf, u64)>,

    /// The cumulative sizes of the files, in ascending order matching
    /// `paths_and_sizes`. Since there are no zero-sized files, all entries are
    /// distinct, and this vector is strictly crescent.
    cumulative_sizes: Vec<u64>,

    /// The total size of the mapping.
    total_size: u64,

    /// Copy of the max mapping size defined in the cache, for easier access.
    max_mapping_size: usize,
}

impl FileGroup {
    /// Creates a new `FileGroup` from a group of file names.
    ///
    /// Existing directories will be traversed at the moment of this call, so
    /// that relative paths and symbolic links are resolved immediately.
    /// Changing working directory at a later time will not affect an existing
    /// `FileGroup`.
    ///
    /// It is OK to create a `FileGroup` when only some of the files exists or
    /// have sizes smaller than informed. When mutably borrowing (available in
    /// read-write mode), directories and files will be created or extended as
    /// needed. When borrowing non-mutably, an Error is returned if part of the
    /// range is not available.
    ///
    /// See `Mode` struct for more options.
    pub fn new(
        shared_cache: Arc<Cache>,
        files_with_sizes: &[(impl AsRef<Path>, u64)],
        operation_mode: Mode,
    ) -> Result<FileGroup, Error> {
        // Remove zero sized files, because they are never mapped and only
        // complicates stuff, and canonicalize all paths so they are independent
        // of current workdir.
        //let mut existing_paths = HashSet::new();
        let files_with_sizes = files_with_sizes
            .iter()
            .filter_map(|(path, size)| {
                if *size != 0 {
                    Some((path.as_ref(), *size))
                } else {
                    None
                }
            })
            .collect();

        Self::new_impl(shared_cache, files_with_sizes, operation_mode)
    }

    fn new_impl(
        shared_cache: Arc<Cache>,
        files_with_sizes: Vec<(&Path, u64)>,
        operation_mode: Mode,
    ) -> Result<FileGroup, Error> {
        // We assume every existing file to be fully allocated. If reserve is
        // set, we must ensure this is true for existing files.
        if let Mode::ReadWrite { reserve: true } = &operation_mode {
            for (path, required_size) in files_with_sizes.iter() {
                if let Ok(mut file) = OpenOptions::new().read(true).write(true).open(path) {
                    let metadata = file.metadata()?;
                    preallocate_file(&mut file, 0, min(metadata.len(), *required_size))?;
                }
            }
        }

        // Resolve paths as best as possible:
        let resolved_paths =
            path_resolver::resolve_known_paths(files_with_sizes.iter().map(|(path, _)| *path))?;
        assert_eq!(resolved_paths.len(), files_with_sizes.len());
        let paths_and_sizes = resolved_paths
            .into_iter()
            .zip(files_with_sizes.into_iter().map(|(_, size)| size))
            .collect::<Vec<_>>();

        // Calculate matching vector of cumulative sizes.
        let mut total_size = 0u64;
        let cumulative_sizes: Vec<u64> = paths_and_sizes
            .iter()
            .map(|(_, len)| {
                let val = total_size;
                total_size += *len;
                val
            })
            .collect();

        let (unique_id, max_mapping_size) = {
            let mut cache = shared_cache.inner.lock().unwrap();

            (cache.get_unique_id(), cache.get_options().max_mapping_size)
        };

        Ok(FileGroup {
            unique_id,
            cache: shared_cache,
            operation_mode,
            paths_and_sizes,
            cumulative_sizes,
            total_size,
            max_mapping_size,
        })
    }

    /// Convert all kinds of ranges to absolute values.
    fn unpack_range(&self, range: impl RangeBounds<u64>) -> (u64, u64) {
        let start = match range.start_bound() {
            std::ops::Bound::Included(x) => *x,
            std::ops::Bound::Excluded(x) => *x + 1,
            std::ops::Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            std::ops::Bound::Included(x) => *x + 1,
            std::ops::Bound::Excluded(x) => *x,
            std::ops::Bound::Unbounded => self.total_size,
        };
        (start, end)
    }

    fn raw_get<'a, S: U8Slice<'a>>(
        &self,
        start: u64,
        end: u64,
        can_write: bool,
    ) -> Result<(ChunksReleaser, Vec<S>), Error> {
        // Sanitize range bounds:
        if start > end || end > self.total_size {
            return Err(Error::InvalidRange);
        }
        if start == end {
            return Ok((
                // Dummy fused iter:
                ChunksReleaser(self.chunks(0, 0, 0).0),
                Vec::new(),
            ));
        }
        let len = end - start;

        // Find the first file of the range:
        let (file_idx, offset) = match self.cumulative_sizes.binary_search(&start) {
            Err(idx) => (idx - 1, start - self.cumulative_sizes[idx - 1]),
            Ok(idx) => (idx, 0),
        };
        // The offset must be within the file:
        assert!(offset < self.paths_and_sizes[file_idx].1);

        // TODO: have an optional feature to lock the requested range here...
        //
        // Unless we implement some kind range based read/write lock, we can't
        // have a safe `get_mut()` that obeys rust's aliasing rules. But that is
        // costly, and I won't do it for now.
        //
        // It is also mostly unnecessary, because Torrent clients (to which this
        // library it targeted) will already have the kind of control to not
        // concurrently write+write and read+write to the same place.

        // Split the range in file chunks, and the get slices from the cache.
        let (chunk_iter, mut initial_offset) = self.chunks(file_idx, offset, len);

        // Cache the opened file between loop iterations, because there is a
        // considerable chance next chunk will come from the same file,
        // specially on 32 bits systems.
        let mut file_cache = SingleCache::new();
        let mut len_cache = SingleCache::new();

        let mut slices = Vec::new();
        let mut cache = self.cache.inner.lock().unwrap();
        for (loop_count, chunk) in chunk_iter.clone().enumerate() {
            let get_result = cache.get_inc(self.unique_id, chunk.group_offset, || {
                let mut options = MmapOptions::new();
                options
                    .offset(chunk.file_offset)
                    .len(chunk.mapping_len as usize);

                let file = file_cache.get_mut(chunk.file_idx, |key| {
                    let path = &self.paths_and_sizes[*key].0;

                    let mut open_options = OpenOptions::new();
                    open_options.read(true).write(can_write).create(can_write);

                    // First attempt at opening the file.
                    let result = open_options.open(path);

                    // If file was not found, but we can write and there is a
                    // valid parent path, we try again, this time trying to
                    // create the possibly missing path to the file. (All this
                    // could be written in a single match line, but I don't like
                    // calling path.parent() if not strictly necessary.)
                    if let Err(err) = &result {
                        if can_write && err.kind() == ErrorKind::NotFound {
                            if let Some(parent_dir) = path.parent() {
                                create_dir_all(parent_dir)?;
                                return open_options.open(path);
                            }
                        }
                    }

                    result
                })?;

                let file_len =
                    *len_cache.get_mut(chunk.file_idx, |_| file.metadata().map(|m| m.len()))?;

                let min_expected_file_len = chunk.file_offset + chunk.mapping_len as u64;

                if file_len < min_expected_file_len {
                    if can_write {
                        file.set_len(min_expected_file_len)?;
                        if let Mode::ReadWrite { reserve: true } = self.operation_mode {
                            platform::preallocate_file(
                                file,
                                file_len,
                                min_expected_file_len - file_len,
                            )?;
                        }

                        // Invalidate len cache because file size changed.
                        len_cache = SingleCache::new();
                    } else {
                        return Err(Error::FileTooSmall);
                    }
                }

                if can_write {
                    Ok(options.map_raw(&*file)?)
                } else {
                    Ok(options.map_raw_read_only(&*file)?)
                }
            });

            match get_result {
                Ok(ptr) => {
                    // First chunk is special because we have to apply
                    // offset to it.
                    //
                    // SAFETY: initial_offset will always be smaller
                    // than the length of the first chunk, so this is
                    // safe.
                    let mut len = chunk.user_len - initial_offset;
                    let mut ptr = unsafe { ptr.offset(initial_offset as isize) };
                    // Next chunks won't be adjusted:
                    initial_offset = 0;

                    // SAFETY: this is safe because the pointer won't be freed until
                    // the corresponding `put_dec()` is issued.
                    unsafe {
                        if cfg!(all(windows, target_pointer_width = "64")) {
                            // On Windows 64 bits, it is possible that a single
                            // chunk to be bigger than the maximum size of its
                            // 32-bit IoSlice. We have to break it up in smaller
                            // IoSlices.
                            while len > u32::MAX as usize {
                                slices.push(S::from_raw_parts(ptr, u32::MAX as u64));

                                ptr = ptr.offset(u32::MAX as isize);
                                len -= u32::MAX as usize;
                            }
                        }

                        slices.push(S::from_raw_parts(ptr, len as u64));
                    }
                }
                Err(err) => {
                    // In case of mapping error, we have to manually release the
                    // chunks that where successfully acquired, because the
                    // `ChunksReleaser` object that would do it on drop hasn't
                    // been created yet.
                    //
                    // Due to this lack of RAII, I am tempted to mark
                    // `CacheImpl::get_inc()` as unsafe, but since `Box::leak()`
                    // isn't, I wont.
                    for chunk in chunk_iter.take(loop_count) {
                        cache.put_dec(self.unique_id, chunk.group_offset);
                    }

                    return Err(err.into());
                }
            }
        }

        Ok((ChunksReleaser(chunk_iter), slices))
    }

    /// Borrows a read-only reference to a range.
    ///
    /// Currently this function is only implemented for read-only FileGroup.
    pub fn borrow(&self, range: impl RangeBounds<u64>) -> Result<Ref, Error> {
        if !self.is_read_only() {
            unimplemented!();
        }
        // SAFETY: This is safe because self is a read-only FileGroup.
        unsafe { self.borrow_unchecked(range) }
    }

    /// Borrows a read-write reference to a range.
    ///
    /// Currently safe function is not implemented.
    pub fn borrow_mut(&self, _range: impl RangeBounds<u64>) -> Result<RefMut, Error> {
        unimplemented!();
    }

    /// Unsafely borrows a read-only reference to a range.
    ///
    /// This is unsafe because the caller must ensure there is no writer to this
    /// same range across all threads, so that the returned range does not
    /// violates rust's aliasing rules.
    pub unsafe fn borrow_unchecked(&self, range: impl RangeBounds<u64>) -> Result<Ref, Error> {
        let (start, end) = self.unpack_range(range);
        let (releaser, slices) = self.raw_get(start, end, false)?;
        Ok(Ref {
            _releaser: releaser,
            slices,
        })
    }

    /// Unsafely borrows a read-write reference to a range.
    ///
    /// If some files does not exits or are smaller than expected, they are
    /// created and extended to the needed size. If `reserve` was specified when
    /// creating the FileGroup, any file extension will be allocated on disk.
    ///
    /// This is unsafe because the caller must ensure there is no other reader
    /// or writer to this same range across all threads, so that the returned
    /// range does not violates rust's aliasing rules.
    pub unsafe fn borrow_mut_unchecked(
        &self,
        range: impl RangeBounds<u64>,
    ) -> Result<RefMut, Error> {
        if self.is_read_only() {
            return Err(Error::ReadOnlyMode);
        }
        let (start, end) = self.unpack_range(range);
        let (releaser, slices) = self.raw_get(start, end, true)?;
        Ok(RefMut {
            _releaser: releaser,
            slices,
        })
    }

    /// Returns the iterator among file's chunks, and the offset of the first
    /// byte into the first chunk.
    fn chunks(&self, file_idx: usize, offset: u64, len: u64) -> (ChunkIter, usize) {
        // Zero the lower bits of offset to be aligned to max_mapping_size.
        let mask = self.max_mapping_size as u64 - 1;
        let next_file_offset = offset & !mask;
        let initial_chunk_offset = (offset & mask) as usize;
        let remaining_bytes = len + initial_chunk_offset as u64;
        (
            ChunkIter {
                group: self,
                next_file_idx: file_idx,
                next_file_offset,
                remaining_bytes,
            },
            initial_chunk_offset,
        )
    }

    pub fn is_read_only(&self) -> bool {
        Mode::ReadOnly == self.operation_mode
    }
}

impl Drop for FileGroup {
    fn drop(&mut self) {
        // Remove all cached elements for this FileGroup. The trouble if we
        // don't do it is that if a file is deleted from the system while still
        // mapped in our cache, it will still take up space on storage.
        self.cache
            .inner
            .lock()
            .unwrap()
            .remove_file_group(self.unique_id);
    }
}

trait U8Slice<'a>
where
    Self: Sized,
{
    unsafe fn from_raw_parts(ptr: *const u8, len: u64) -> Self;
}

impl<'a> U8Slice<'a> for IoSlice<'a> {
    unsafe fn from_raw_parts(ptr: *const u8, len: u64) -> Self {
        Self::new(&*ptr::slice_from_raw_parts(ptr, len as usize))
    }
}

impl<'a> U8Slice<'a> for IoSliceMut<'a> {
    unsafe fn from_raw_parts(ptr: *const u8, len: u64) -> Self {
        Self::new(&mut *ptr::slice_from_raw_parts_mut(
            ptr as *mut u8,
            len as usize,
        ))
    }
}

/// Break up range `FileGroup` to inner files chunks aligned to
/// the mapping size.
#[derive(Debug, Clone)]
struct ChunkIter<'a> {
    group: &'a FileGroup,
    next_file_idx: usize,
    next_file_offset: u64,
    remaining_bytes: u64,
}

/// Fully determines one whole chunk of a mapped file.
#[derive(Debug, Clone)]
struct Chunk {
    /// The index of the file this chunk belongs to.
    file_idx: usize,
    /// The offset of this chunk inside the file.
    file_offset: u64,
    /// The offset of this chunk inside the whole group.
    group_offset: u64,
    /// The actual size of the mapping.
    mapping_len: usize,
    /// The size the user requested.
    user_len: usize,
}

impl<'a> Iterator for ChunkIter<'a> {
    type Item = Chunk;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining_bytes == 0 {
            return None;
        }

        let file_idx = self.next_file_idx;
        let file_offset = self.next_file_offset;

        let file_size = self.group.paths_and_sizes[file_idx].1;
        let mapping_len;
        self.next_file_offset += self.group.max_mapping_size as u64;
        if self.next_file_offset < file_size {
            mapping_len = self.group.max_mapping_size;
        } else {
            mapping_len = (file_size - file_offset) as usize;
            self.next_file_offset = 0;
            self.next_file_idx += 1;
        }

        let user_len;
        if self.remaining_bytes > mapping_len as u64 {
            user_len = mapping_len;
            self.remaining_bytes -= mapping_len as u64;
        } else {
            user_len = self.remaining_bytes as usize;
            self.remaining_bytes = 0;
        };

        Some(Chunk {
            file_idx,
            file_offset,
            group_offset: self.group.cumulative_sizes[file_idx] + file_offset,
            mapping_len,
            user_len,
        })
    }
}

impl<'a> FusedIterator for ChunkIter<'a> {}

struct ChunksReleaser<'a>(ChunkIter<'a>);

impl<'a> Drop for ChunksReleaser<'a> {
    fn drop(&mut self) {
        // Release all the chunks locked for this ref.
        let group = self.0.group;
        let mut cache = group.cache.inner.lock().unwrap();
        for chunk in self.0.clone() {
            cache.put_dec(group.unique_id, chunk.group_offset);
        }
    }
}

/// Holds a borrowed range.
///
/// Lifetime `'a` is the lifetime of the parent `FileGroup`, and `'s` is
/// supposed to be the lifetime of this struct itself, but it must be bound to
/// `&'s self` by the accessor functions.
///
/// Deref should NOT be implemented for this type! It could cause dangling
/// references and all kinds of memory hazards!
///
/// The reason is that Deref expects the referenced object to be able to outlive
/// `Self` (i.e., `obj.deref().to_owned()` should live independently of `obj`).
/// This is not the case here: our pointed object `[IoSlice<'s>]` contains
/// references whose lifetime should be bound to the `Ref` object.
pub struct Ref<'a, 's>
where
    'a: 's,
{
    _releaser: ChunksReleaser<'a>,
    slices: Vec<IoSlice<'s>>,
}

impl<'a, 's> Ref<'a, 's> {
    pub fn get(&'s self) -> &'s [IoSlice<'s>] {
        &self.slices
    }
}

//DON'T DO THIS, this is wrong! It would allow the returned `IoSlice<'s>` to
// outlive its `Ref<'a, 's>`:
/*
impl<'a, 's> Deref for Ref<'a, 's> {
    type Target = [IoSlice<'s>];

    fn deref(&self) -> &[IoSlice<'s>] {
        &self.slices
    }
}
*/

/// Holds a borrowed mutable range.
///
/// See `Ref` documentation for lifetime considerations.
pub struct RefMut<'a, 's>
where
    'a: 's,
{
    _releaser: ChunksReleaser<'a>,
    slices: Vec<IoSliceMut<'s>>,
}

impl<'a, 's> RefMut<'a, 's> {
    pub fn get(&'s mut self) -> &'s mut [IoSliceMut<'s>] {
        &mut self.slices
    }
}

fn is_power_of_two<T: num_traits::Unsigned + std::ops::BitAnd<Output = T> + Copy>(val: T) -> bool {
    !val.is_zero() && (val & (val - T::one())).is_zero()
}
