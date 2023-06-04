pub mod cache;
mod platform;

use cache::Cache;
use memmap2::MmapOptions;
use platform::preallocate_file;
use std::{
    fs::{self, OpenOptions},
    io::{self, ErrorKind, IoSlice, IoSliceMut},
    iter::FusedIterator,
    ops::{Deref, DerefMut, RangeBounds},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    ptr,
    sync::Arc,
};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("system error when accessing a file")]
    IOError(#[from] std::io::Error),
    #[error("file have unexpected size")]
    WrongSize,
    #[error("not a regular file")]
    NotAFile,
    #[error("path component is not a directory")]
    NotADirectory,
    #[error("a write was attempted on read-only mode")]
    ReadOnlyMode,
    #[error("the range requested is invalid")]
    InvalidRange,
}

/// The operation mode of a `FileGroup`.
#[derive(Clone, Copy, Debug)]
pub enum Mode {
    /// Files are opened and mapped as read-only. If they don't exist or are
    /// smaller than expected, error `Error::WrongSize` is returned.
    ReadOnly,
    /// Files are opened and mapped in read and write mode. If they don't exist
    /// or are smaller than expected, they are created and extended to the
    /// expected size.
    ///
    /// If `reserve` is set, all non-allocated blocks on sparse files will be
    /// allocated. This is recommended, because if the application tries to
    /// write to an unallocated block, but it can't be allocated because the
    /// storage is full, your application will be signaled with SIGBUS on POSIX,
    /// and God knows what happens on Windows.
    ///
    /// If `truncate` is set, files larger than what they are supposed to be are
    /// truncated.
    ReadWrite { reserve: bool, truncate: bool },
}

/// A sequence of files with known sizes grouped together as a single
/// 64-bit addressable byte array.
#[derive(Debug)]
pub struct FileGroup {
    /// Cache shared among other `FileGroup` storing actual file mappings. It
    /// has to be shared if we want to control the amount of resources used
    /// globally by the all the file groups sharing it.
    cache: Arc<Cache>,

    /// Unique identifier inside the cache.
    unique_id: u64,

    /// Tells if this is in read-only mode.
    is_read_only: bool,

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
    /// Relative paths and symbolic links are resolved at the moment of the
    /// call.
    ///  
    /// If `strict_size` is set, error `Error::WrongSize` if there are files
    /// larger than the expected.
    pub fn new(
        shared_cache: Arc<Cache>,
        files_with_sizes: &[(impl AsRef<Path>, u64)],
        operation_mode: Mode,
        strict_size: bool,
    ) -> Result<FileGroup, Error> {
        let is_read_only = if let Mode::ReadOnly = &operation_mode {
            true
        } else {
            false
        };

        // Sanity check every path without modifying the filesystem, to
        // trigger an error in cases we can before writing anything.
        for (path, required_size) in files_with_sizes {
            let path = path.as_ref();
            // We actually try to open the file instead of just retrieving
            // metadata, because in unixes it seems this is the only reliable
            // way to know if a file is writable.
            let open_result = OpenOptions::new()
                .read(true)
                .write(!is_read_only)
                .open(path);

            match open_result {
                Ok(file) => {
                    let metadata = file.metadata()?;
                    if !metadata.is_file() {
                        return Err(Error::NotAFile);
                    }
                    if (strict_size && metadata.len() > *required_size)
                        || (is_read_only && metadata.len() < *required_size)
                    {
                        return Err(Error::WrongSize);
                    }
                }
                Err(err) => {
                    if is_read_only || err.kind() != ErrorKind::NotFound {
                        return Err(err.into());
                    }

                    has_writable_first_existing_ancestor(path.parent().ok_or(err)?)?;
                }
            }
        }

        // Create and truncate every file if in writing mode. In read only mode
        // all files have already been checked, and we are all good.
        if let Mode::ReadWrite { reserve, truncate } = operation_mode {
            for (path, required_size) in files_with_sizes {
                let path = path.as_ref();
                if let Some(dir) = path.parent() {
                    fs::create_dir_all(dir)?;
                }

                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .open(path)?;

                let metadata = file.metadata()?;

                if (metadata.len() < *required_size)
                    || (truncate && metadata.len() > *required_size)
                {
                    file.set_len(*required_size)?;
                }

                if reserve {
                    preallocate_file(file.as_raw_fd(), *required_size)?;
                }
            }
        }

        // Remove zero sized files, because they are never mapped and only
        // complicates stuff, and canonicalize all paths so they are independent
        // of current workdir.
        let paths_and_sizes = files_with_sizes
            .iter()
            .filter_map(|(path, size)| {
                if *size == 0 {
                    None
                } else {
                    Some(fs::canonicalize(path).map(|path| (path, *size)))
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

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
            is_read_only,
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
            Err(idx) => (idx - 1, start - self.cumulative_sizes[idx]),
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

        // Split the range in file chuncks, and the get slices from the cache.
        let (chunk_iter, mut initial_offset) = self.chunks(file_idx, offset, len);

        let mut slices = Vec::new();
        let mut cache = self.cache.inner.lock().unwrap();
        for (loop_count, chunk) in chunk_iter.clone().enumerate() {
            let get_result = cache.get_inc(self.unique_id, chunk.group_offset, || {
                let mut options = MmapOptions::new();
                options.offset(chunk.file_offset).len(chunk.len as usize);

                let file = OpenOptions::new()
                    .read(true)
                    .write(!self.is_read_only)
                    .create(true)
                    .open(&self.paths_and_sizes[chunk.file_idx].0)?;

                if self.is_read_only {
                    options.map_raw_read_only(&file)
                } else {
                    options.map_raw(&file)
                }
            });

            match get_result {
                Ok((ptr, mut len)) => {
                    // First chunk is special because we have to apply
                    // offset to it.
                    //
                    // SAFETY: initial_offset will always be smaller
                    // than the length of the first chunk, so this is
                    // safe.
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
    pub fn borrow(&self, range: impl RangeBounds<u64>) -> Result<Ref, Error> {
        let (start, end) = self.unpack_range(range);
        let (releaser, slices) = self.raw_get(start, end)?;
        Ok(Ref {
            _releaser: releaser,
            slices,
        })
    }

    /// Borrows a read-write reference to a range.
    ///
    /// This is unsafe because the caller must ensure there is no other reader
    /// or writer to this same range across all threads, so that the returned
    /// range does not violates rust's aliasing rules.
    pub unsafe fn borrow_mut_unchecked(
        &self,
        range: impl RangeBounds<u64>,
    ) -> Result<RefMut, Error> {
        if self.is_read_only {
            return Err(Error::ReadOnlyMode);
        }
        let (start, end) = self.unpack_range(range);
        let (releaser, slices) = self.raw_get(start, end)?;
        Ok(RefMut {
            _releaser: releaser,
            slices,
        })
    }

    /// Returns the iterator among file's chunks, and the offset of the fisrt
    /// byte into the first chunk.
    fn chunks(&self, file_idx: usize, offset: u64, len: u64) -> (ChunkIter, u32) {
        // Zero the lower bits of offset to be aligned to max_mapping_size.
        let mask = self.max_mapping_size as u64 - 1;
        let next_file_offset = offset & !mask;
        let initial_chunk_offset = (offset & mask) as u32;
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

#[derive(Debug, Clone)]
struct Chunk {
    file_idx: usize,
    file_offset: u64,
    group_offset: u64,
    len: u64,
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
        let mut len;
        self.next_file_offset += self.group.max_mapping_size as u64;
        if self.next_file_offset < file_size {
            len = self.group.max_mapping_size as u64;
        } else {
            len = file_size - file_offset;
            self.next_file_offset = 0;
            self.next_file_idx += 1;
        }

        if self.remaining_bytes > len {
            self.remaining_bytes -= len;
        } else {
            len = self.remaining_bytes;
            self.remaining_bytes = 0;
        }

        Some(Chunk {
            file_idx,
            file_offset,
            group_offset: self.group.cumulative_sizes[file_idx] + file_offset,
            len,
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
/// references and all kind of memory hazards!
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

/// Try its best to decide if the first existing ancestor of a path is a
/// writable directory.
///
/// Returns error if an existing part of the path is not a directory, if the
/// last existing directory is not writable.
fn has_writable_first_existing_ancestor(path: &Path) -> Result<(), Error> {
    let mut last_err: io::Error = ErrorKind::NotFound.into();
    for ancestor in path.ancestors() {
        let ancestor = if !ancestor.as_os_str().is_empty() {
            ancestor
        } else {
            &Path::new(".")
        };

        match fs::metadata(ancestor) {
            Ok(metadata) => {
                // First existing path section found. Fail if is a dir or not
                // writable, otherwise succeed.
                return if !metadata.is_dir() {
                    Err(Error::NotADirectory)
                } else if metadata.permissions().readonly() {
                    // TODO: try to test for permissions more reliably, possibly
                    // using platform specific calls.
                    Err(Error::IOError(ErrorKind::PermissionDenied.into()))
                } else {
                    Ok(())
                };
            }
            Err(err) => {
                if err.kind() != ErrorKind::NotFound {
                    return Err(err.into());
                }
                last_err = err;
            }
        }
    }

    // Could not find any directory in the path (how is that possible???).
    Err(Error::IOError(last_err))
}

fn is_power_of_two<T: num_traits::Unsigned + std::ops::BitAnd<Output = T> + Copy>(val: T) -> bool {
    !val.is_zero() && (val & (val - T::one())).is_zero()
}

#[cfg(test)]
mod tests {
    use std::{io::IoSliceMut, sync::Arc};

    use crate::{cache::Cache, FileGroup};

    #[test]
    fn create_write() {
        {
            let cache = Arc::new(Cache::default());
            let fg = FileGroup::new(
                cache,
                &[("/tmp/xoxoxo", 43)],
                crate::Mode::ReadWrite {
                    reserve: true,
                    truncate: true,
                },
                true,
            )
            .unwrap();

            let mut my_slices = Vec::new();
            {
                let mut r = unsafe { fg.borrow_mut_unchecked(0..4).unwrap() };
                let aaa = r.get();
                for s in aaa {
                    s[0] = 42;
                    my_slices.push(std::mem::replace(s, IoSliceMut::new(&mut [])));
                }
            }
            //my_slices[0][1] = 43;
        }
    }
}
