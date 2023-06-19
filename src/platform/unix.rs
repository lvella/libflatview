use std::fs::File;

use lazy_static::lazy_static;

use crate::{is_power_of_two, Error};

lazy_static! {
    /// The page size.
    pub static ref PAGESIZE: usize = {
        let page = rustix::param::page_size();
        // Assert a page is a power of two (kinda silly, I know)
        assert!(is_power_of_two(page));
        page
    };
}

impl From<rustix::io::Errno> for Error {
    fn from(value: rustix::io::Errno) -> Self {
        Error::IOError(value.into())
    }
}

// TODO: use libc::_SC_ADVISORY_INFO to tell if posix_fallocate is present.
pub fn preallocate_file(file: &mut File, size: u64) -> Result<(), Error> {
    Ok(rustix::fs::fallocate(
        file,
        rustix::fs::FallocateFlags::empty(),
        0,
        size,
    )?)
}
