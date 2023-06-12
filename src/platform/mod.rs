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

fn foolproof_fallocate(file: &mut File, size: u64) -> Result<(), Error> {
    if file.metadata()?.len() < size {
        file.set_len(size)?;
    }

    let mut buffer = [0; 8 * 1024];

    let mut pos = file.seek(SeekFrom::Start(0))?;
    while pos < size {
        let count = min(buffer.len() as u64, size - pos) as usize;
        let buffer = &mut buffer[..count];

        // Read a chunk of the file.
        let count = file.read(buffer)?;
        if count == 0 {
            break;
        }

        // Write it back to the same place.
        file.seek(SeekFrom::Start(pos))?;
        file.write_all(buffer)?;

        pos += count as u64;
    }
    Ok(())
}
