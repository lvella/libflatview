pub mod cache;
mod platform;

use cache::{Cache, CacheImpl};
use core::slice;
use memmap2::MmapOptions;
use platform::preallocate_file;
use std::{
    fmt::Alignment,
    fs::{self, OpenOptions},
    io::{self, ErrorKind, IoSlice, IoSliceMut},
    iter::FusedIterator,
    ops::{Range, RangeBounds},
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
    #[error("a write write was attempted on read-only mode")]
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

        let unique_id = shared_cache
            .identifier_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let max_mapping_size = shared_cache
            .inner
            .lock()
            .unwrap()
            .get_options()
            .max_mapping_size;

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

    pub fn get(&self, range: impl RangeBounds<u64>) -> Result<Ref, Error> {
        // Sanitize range bounds:
        let mut start = match range.start_bound() {
            std::ops::Bound::Included(x) => *x,
            std::ops::Bound::Excluded(x) => *x + 1,
            std::ops::Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            std::ops::Bound::Included(x) => *x + 1,
            std::ops::Bound::Excluded(x) => *x,
            std::ops::Bound::Unbounded => self.total_size,
        };

        if start > end || end > self.total_size {
            return Err(Error::InvalidRange);
        }
        if start == end {
            return Ok(Ref {
                // Dummy fused iter:
                chunk_iter: self.chunks(0, 0, 0).0,
                slices: Vec::new(),
            });
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
        let (chunk_iter, initial_offset) = self.chunks(file_idx, offset, len);
        let mut slices;
        let mut err = None;
        {
            let mut cache = self.cache.inner.lock().unwrap();
            slices = chunk_iter
                .clone()
                .map_while(|chunk| {
                    match cache.get_inc(self.unique_id, chunk.group_offset, || {
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
                    }) {
                        Ok(ptr) => Some(ptr::slice_from_raw_parts(ptr.0, ptr.1)),
                        Err(e) => {
                            err = Some(e);
                            None
                        }
                    }
                })
                .collect::<Vec<_>>();

            if let Some(err) = err {
                // In case of mapping error, we have to manually release the
                // chunks that where successfully acquired, because the Ref
                // object that would do it on drop hasn't been created yet.
                //
                // Because of this lack of RAII, I am tempted to mark
                // `get_inc()` as unsafe, but since `Box::leak()` isn't, I wont.
                for (chunk, _) in chunk_iter.zip(slices) {
                    cache.put_dec(self.unique_id, chunk.group_offset);
                }

                return Err(err.into());
            }
        } // Mutex unlock.

        // The first slice must be readjusted to the user requested start, as
        // the start had to be aligned to the page boundary.
        //
        // SAFETY: the slice will be held by cache until its corresponding
        // `put_dec() call`, so it is safe to be dereferenced.
        slices[0] = &unsafe { &*slices[0] }[initial_offset as usize..];

        Ok(Ref { chunk_iter, slices })
    }

    /// Returns the iterator among file's chunks, and the offset of the fisrt
    /// byte into the first chunk.
    fn chunks(&self, file_idx: usize, offset: u64, len: u64) -> (ChunkIter, u64) {
        // Zero the lower bits of offset to be aligned to max_mapping_size.
        let mask = self.max_mapping_size as u64 - 1;
        let next_file_offset = offset & !mask;
        let initial_chunk_offset = offset & mask;
        let remaining_bytes = len + initial_chunk_offset;
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
        todo!()
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

pub struct Ref<'a> {
    chunk_iter: ChunkIter<'a>,
    slices: Vec<*const [u8]>,
}

impl<'a> Drop for Ref<'a> {
    fn drop(&mut self) {
        // Release all the chunks locked for this ref.
        let group = self.chunk_iter.group;
        let mut cache = group.cache.inner.lock().unwrap();
        for chunk in self.chunk_iter.clone() {
            cache.put_dec(group.unique_id, chunk.group_offset);
        }
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
    use std::sync::Arc;

    use crate::{cache::Cache, FileGroup};

    #[test]
    fn create_write() {
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
        fg.get(4..1);
    }
}
