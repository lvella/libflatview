#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub use unix::*;
#[cfg(windows)]
pub use windows::*;

use crate::Error;
use std::{
    cmp::min,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
};
