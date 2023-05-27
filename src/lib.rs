mod cache;

use cache::Cache;
use lazy_static::lazy_static;
use nix::{libc::off_t, sys::mman::ProtFlags};
use std::{
    ffi::c_void,
    fs::{self, OpenOptions},
    io::{self, ErrorKind},
    num::NonZeroUsize,
    os::{
        fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
        unix::prelude::MetadataExt,
    },
    path::{Path, PathBuf},
    sync::Arc,
};

/// Limits the maximum map size, in bytes, to 1/256 of pointer size.
const MAX_MAP_SIZE: u64 = 1 << (usize::BITS - 8);

lazy_static! {
    /// The page size.
    static ref PAGESIZE: u64 = {
        let page = nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE).unwrap().unwrap() as u64;
        // I don't really expect the page size to be bigger than 1/256 of
        // pointer size, but just in case:
        assert!(page < MAX_MAP_SIZE);
        page
    };
}

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
}

impl From<nix::errno::Errno> for Error {
    fn from(value: nix::errno::Errno) -> Self {
        Error::IOError(std::io::Error::from_raw_os_error(value as i32))
    }
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

    /// The path and size of of every file.
    paths_and_sizes: Vec<(PathBuf, u64)>,

    /// The cumulative sizes of the files, in ascending order matching
    /// `paths_and_sizes`.
    cumulative_sizes: Vec<u64>,
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
        files_with_sizes: &[(&Path, u64)],
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
                    if (strict_size && metadata.size() > *required_size)
                        || (is_read_only && metadata.size() < *required_size)
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
                if let Some(dir) = path.parent() {
                    fs::create_dir_all(dir)?;
                }

                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .open(path)?;

                let metadata = file.metadata()?;

                if (metadata.size() < *required_size)
                    || (truncate && metadata.size() > *required_size)
                {
                    file.set_len(*required_size)?;
                }

                if reserve {
                    // TODO: make this platform independent
                    nix::fcntl::posix_fallocate(file.as_raw_fd(), 0, *required_size as i64)?;
                }
            }
        }

        // Canonicalize all paths.
        let paths_and_sizes = files_with_sizes
            .iter()
            .map(|(path, size)| fs::canonicalize(path).map(|path| (path, *size)))
            .collect::<Result<Vec<_>, _>>()?;

        // Calculate matching vector of cumulative sizes.
        let cumulative_sizes: Vec<u64> = paths_and_sizes
            .iter()
            .scan(0u64, |curr, (_, len)| {
                let val = *curr;
                *curr += *len;
                Some(val)
            })
            .collect();

        Ok(FileGroup {
            cache: shared_cache,
            paths_and_sizes,
            cumulative_sizes,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileMode {
    ReadOnly,
    ReadWrite,
}

fn file_open(path: &Path, mode: FileMode) -> nix::Result<OwnedFd> {
    let oflag = match mode {
        FileMode::ReadOnly => nix::fcntl::OFlag::O_RDONLY,
        FileMode::ReadWrite => nix::fcntl::OFlag::O_RDWR,
    };
    nix::fcntl::open(path, oflag, nix::sys::stat::Mode::empty())
        .map(|raw_fd| unsafe { OwnedFd::from_raw_fd(raw_fd) })
}

enum PtrType<T> {
    ConstPtr(*const T),
    MutPtr(*mut T),
}

impl<T> PtrType<T> {
    fn const_ptr(&self) -> *const T {
        match self {
            PtrType::ConstPtr(ptr) => *ptr,
            PtrType::MutPtr(ptr) => *ptr as *const T,
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
                } else if !metadata.permissions().readonly() {
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

struct MMap {
    ptr: PtrType<u8>,
    len: NonZeroUsize,
}

impl MMap {
    fn from_fd(
        fd: BorrowedFd,
        mode: FileMode,
        from: off_t,
        len: NonZeroUsize,
    ) -> nix::Result<MMap> {
        let flags = match mode {
            FileMode::ReadOnly => ProtFlags::PROT_READ,
            FileMode::ReadWrite => ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
        };

        let ptr;
        unsafe {
            let void_ptr = nix::sys::mman::mmap(
                None,
                len,
                flags,
                nix::sys::mman::MapFlags::MAP_SHARED,
                fd.as_raw_fd(),
                from,
            )?;

            ptr = match mode {
                FileMode::ReadOnly => PtrType::ConstPtr(void_ptr as *const u8),
                FileMode::ReadWrite => PtrType::MutPtr(void_ptr as *mut u8),
            }
        }

        Ok(MMap { ptr, len })
    }

    fn get_mut(&self) -> Option<&mut [u8]> {
        match &self.ptr {
            PtrType::ConstPtr(_) => None,
            PtrType::MutPtr(ptr) => {
                Some(unsafe { std::slice::from_raw_parts_mut(*ptr, self.len.into()) })
            }
        }
    }
}

impl Drop for MMap {
    fn drop(&mut self) {
        unsafe {
            nix::sys::mman::munmap(self.ptr.const_ptr() as *mut c_void, self.len.into()).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn empty() {}
}
