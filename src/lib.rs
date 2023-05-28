pub mod cache;
mod platform;

use cache::Cache;
use platform::preallocate_file;
use std::{
    fs::{self, OpenOptions},
    io::{self, ErrorKind},
    ops::{Range, RangeBounds},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
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

        Ok(FileGroup {
            unique_id,
            cache: shared_cache,
            is_read_only,
            paths_and_sizes,
            cumulative_sizes,
            total_size,
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
                lock_guards: Vec::new(),
            });
        }

        // Find the first file of the range:
        let (file_idx, offset) = match self.cumulative_sizes.binary_search(&start) {
            Err(idx) => (idx - 1, start - self.cumulative_sizes[idx]),
            Ok(idx) => (idx, 0),
        };
        // The offset must be within the file:
        assert!(offset < self.paths_and_sizes[file_idx].1);

        // Lock all the required pages in the cache:
        let mut lock_guards = Vec::new();
        {
            let mut cache = self.cache.inner.lock().unwrap();
            /*while start < end {
                cache.
            }*/
            todo!();
        }

        Ok(Ref { lock_guards })
    }
}

impl Drop for FileGroup {
    fn drop(&mut self) {
        // Remove all cached elements for this FileGroup. The trouble if we
        // don't do it, is that if a file is deleted from the system, but still
        // remains mapped in our cache, it will still take up space on storage.
        todo!()
    }
}

pub struct Ref {
    lock_guards: Vec<()>,
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

    // Could not find any directory in the path (how???).
    Err(Error::IOError(last_err))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        cache::{Cache, CacheOptions},
        FileGroup,
    };

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
