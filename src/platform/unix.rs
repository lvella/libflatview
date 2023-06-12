use std::{fs::File, os::fd::AsRawFd};

use lazy_static::lazy_static;

use crate::{is_power_of_two, Error};

lazy_static! {
    /// The page size.
    pub static ref PAGESIZE: u64 = {
        let page = nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE).unwrap().unwrap() as u64;
        // Assert a page is a power of two (kinda silly, I know)
        assert!(is_power_of_two(page));
        page
    };
}

impl From<nix::errno::Errno> for Error {
    fn from(value: nix::errno::Errno) -> Self {
        Error::IOError(std::io::Error::from_raw_os_error(value as i32))
    }
}

// TODO: use libc::_SC_ADVISORY_INFO to tell if posix_fallocate is present.
pub fn preallocate_file(file: &mut File, size: u64) -> Result<(), Error> {
    Ok(nix::fcntl::posix_fallocate(
        file.as_raw_fd(),
        0,
        size as i64,
    )?)
}
