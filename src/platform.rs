use std::os::fd::RawFd;

use lazy_static::lazy_static;

use crate::Error;

lazy_static! {
    /// The page size.
    static ref PAGESIZE: u64 = nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE).unwrap().unwrap() as u64;
}

impl From<nix::errno::Errno> for Error {
    fn from(value: nix::errno::Errno) -> Self {
        Error::IOError(std::io::Error::from_raw_os_error(value as i32))
    }
}

pub fn preallocate_file(fd: RawFd, size: u64) -> Result<(), Error> {
    Ok(nix::fcntl::posix_fallocate(fd, 0, size as i64)?)
}
