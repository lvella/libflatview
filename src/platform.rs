use std::os::fd::RawFd;

use lazy_static::lazy_static;

use crate::Error;

lazy_static! {
    /// The page size.
    pub static ref PAGESIZE: u64 = {
        let page = nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE).unwrap().unwrap() as u64;
        // Assert a page is a positive power of two (kinda silly, I know)
        assert!(page > 0 && (page & (page - 1)) == 0);
        page
    };
}

impl From<nix::errno::Errno> for Error {
    fn from(value: nix::errno::Errno) -> Self {
        Error::IOError(std::io::Error::from_raw_os_error(value as i32))
    }
}

pub fn preallocate_file(fd: RawFd, size: u64) -> Result<(), Error> {
    Ok(nix::fcntl::posix_fallocate(fd, 0, size as i64)?)
}
