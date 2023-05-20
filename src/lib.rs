use lazy_static::lazy_static;
use nix::{libc::off_t, sys::mman::ProtFlags, unistd::Whence};
use std::{
    ffi::c_void,
    fs,
    io::ErrorKind,
    num::NonZeroUsize,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
        unix::prelude::MetadataExt,
    },
    path::{Path, PathBuf},
};

/// Limits the maximum map size in bytes to 1/256 of pointer size.
const MAX_MAP_SIZE: u64 = 1 << (usize::BITS - 8);
/// Limits the maximum mapped size in bytes to 1/8 of pointer size.
const MAX_TOTAL_MAPPED: u64 = 1 << (usize::BITS - 3);

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
    #[error("path is a regular file")]
    NotAFile,
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
    /// or are smaller than then expected, they are created and extended to the
    /// expected size.
    ///
    /// If `reserve` is set, all non-allocated blocks on sparse files will be
    /// allocated.
    ///
    /// If `truncate` is set, files larger than what they are supposed to be are
    /// truncated.
    ReadWrite { reserve: bool, truncate: bool },
}

/// A sequence of files with known sizes grouped together as a single
/// 64-bit addressable byte array.
pub struct FileGroup {
    // The path and size of of every file.
    paths_and_sizes: Vec<(PathBuf, u64)>,
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
        files_with_sizes: &[(&Path, u64)],
        operation_mode: Mode,
        strict_size: bool,
    ) -> Result<FileGroup, Error> {
        let is_read_only = if let Mode::ReadOnly = &operation_mode {
            true
        } else {
            false
        };

        // For every file that exists, either truncate to the right size, or error.
        let mut missing_files = Vec::new();
        for (path, required_size) in files_with_sizes {
            match fs::metadata(path) {
                Ok(metadata) => {
                    if !metadata.is_file() {
                        return Err(Error::NotAFile);
                    }
                    match &operation_mode {
                        Mode::ReadOnly => {
                            if metadata.size() < *required_size
                                || (strict_size && metadata.size() > *required_size)
                            {
                                return Err(Error::WrongSize);
                            }
                        }
                        Mode::ReadWrite {
                            reserve: _,
                            truncate,
                        } => {
                            if metadata.size() > *required_size {
                                if *truncate {
                                    nix::unistd::truncate(
                                        *path,
                                        (*required_size).try_into().unwrap(),
                                    )?;
                                } else if strict_size {
                                    return Err(Error::WrongSize);
                                }
                            } else if metadata.size() < *required_size {
                                nix::unistd::truncate(*path, (*required_size).try_into().unwrap())?;
                            }
                        }
                    }
                }
                Err(err) => {
                    if is_read_only || err.kind() != ErrorKind::NotFound {
                        return Err(err.into());
                    }
                    missing_files.push((*path, *required_size));
                }
            }
        }

        // Create all missing files.
        for (path, required_size) in missing_files {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            nix::unistd::truncate(path, required_size.try_into().unwrap())?;
        }

        // Canonicalize all paths.
        let paths_and_sizes = files_with_sizes
            .iter()
            .map(|(path, size)| fs::canonicalize(path).map(|path| (path, *size)))
            .collect::<Result<Vec<_>, _>>()?;

        // Fill holes.
        if let Mode::ReadWrite {
            reserve,
            truncate: _,
        } = operation_mode
        {
            if reserve {
                for (path, size) in paths_and_sizes.iter() {
                    let fd = file_open(path, FileMode::ReadWrite)?;

                    let mut curr_data = 0;
                    let mut curr_hole;
                    while {
                        curr_hole =
                            nix::unistd::lseek(fd.as_raw_fd(), curr_data, Whence::SeekHole)?;
                        (curr_hole as u64) < *size
                    } {
                        let hole_end =
                            nix::unistd::lseek(fd.as_raw_fd(), curr_hole, Whence::SeekData)?;

                        while curr_hole < hole_end {
                            let map_size = std::cmp::max(hole_end - curr_hole, MAX_MAP_SIZE as i64);

                            let map = MMap::from_fd(
                                fd.as_fd(),
                                FileMode::ReadWrite,
                                curr_hole,
                                NonZeroUsize::new(map_size.try_into().unwrap()).unwrap(),
                            )?;

                            map.get_mut().unwrap().fill(0);

                            curr_hole += map_size;
                        }

                        curr_data = hole_end;
                    }
                }
            }
        }

        // TODO: to be continued...

        Ok(FileGroup { paths_and_sizes })
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
