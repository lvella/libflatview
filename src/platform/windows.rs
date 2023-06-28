use crate::{is_power_of_two, Error};
use lazy_static::lazy_static;
use std::{
    cmp::min,
    ffi::c_void,
    fs::File,
    io::{self, Read, Seek, Write},
    mem::MaybeUninit,
    os::windows::prelude::AsRawHandle,
    ptr,
};
use windows_sys::Win32::{
    Foundation::{GetLastError, ERROR_MORE_DATA, ERROR_NOT_SUPPORTED, HANDLE},
    System::{
        Ioctl::{FILE_ALLOCATED_RANGE_BUFFER, FSCTL_QUERY_ALLOCATED_RANGES},
        SystemInformation::{GetSystemInfo, SYSTEM_INFO},
        IO::DeviceIoControl,
    },
};

const ENTRY_SIZE: u32 = std::mem::size_of::<FILE_ALLOCATED_RANGE_BUFFER>() as u32;

lazy_static! {
    /// The page size.
    pub static ref PAGESIZE: u64 = {
        let page = unsafe {
            let mut system_info = MaybeUninit::<SYSTEM_INFO>::uninit();
            GetSystemInfo(system_info.as_mut_ptr());
            system_info.assume_init().dwPageSize as u64
        };
        // Assert the page size is a power of two (kinda silly, I know)
        assert!(is_power_of_two(page));
        page
    };
}

pub fn preallocate_file(file: &mut File, size: u64) -> Result<(), Error> {
    match mimic_fallocate(file, size) {
        Err(Error::IOError(err)) => {
            // Wine doesn't support FSCTL_QUERY_ALLOCATED_RANGES, and Wine is
            // the main implementation of Windows API I use, so fallback to
            // support it:
            if err.raw_os_error() == Some(ERROR_NOT_SUPPORTED as i32) {
                foolproof_fallocate(file, size)
            } else {
                Err(err.into())
            }
        }
        result => result,
    }
}

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

fn mimic_fallocate(file: &mut File, size: u64) -> Result<(), Error> {
    // To be sure, seek the file to the beginning:
    let mut file_pos = file.seek(io::SeekFrom::Start(0))?;

    let mut default_value = None;
    let mut query_range = [FILE_ALLOCATED_RANGE_BUFFER {
        FileOffset: 0,
        Length: size as i64,
    }];
    unsafe {
        loop {
            let mut allocated_slices = [MaybeUninit::<FILE_ALLOCATED_RANGE_BUFFER>::uninit(); 512];
            let mut actual_size = 0u32;
            let success = DeviceIoControl(
                file.as_raw_handle() as HANDLE,
                FSCTL_QUERY_ALLOCATED_RANGES,
                query_range.as_ptr() as *const c_void,
                ENTRY_SIZE,
                allocated_slices.as_mut_ptr() as *mut c_void,
                // Leave room in the output array so we can fill a dummy EOF
                // entry, so the loop will stop.
                ENTRY_SIZE * (allocated_slices.len() as u32 - 1),
                &mut actual_size,
                ptr::null_mut(),
            ) != 0;

            if !success {
                let error = GetLastError();
                if error != ERROR_MORE_DATA {
                    println!("{error}");
                    return Err(io::Error::from_raw_os_error(error as i32).into());
                }
            }

            // We only use the output after we are sure
            let mut num_outputs = actual_size / ENTRY_SIZE;
            assert_eq!(actual_size % ENTRY_SIZE, 0);

            if success {
                // Add one extra dummy slice to the end so the loop will fill
                // the space up to there.
                allocated_slices[num_outputs as usize].write(FILE_ALLOCATED_RANGE_BUFFER {
                    FileOffset: size as i64,
                    Length: 0,
                });
                num_outputs += 1;
            }

            // We got some ranges from this call, process them:
            let allocated_slices = &allocated_slices[..num_outputs as usize];
            for e in allocated_slices.into_iter().map(|e| e.assume_init_ref()) {
                assert!(file_pos <= e.FileOffset as u64);
                assert!((e.FileOffset + e.Length) as u64 <= size);
                if file_pos < e.FileOffset as u64 {
                    // Everything from file_pos to the first allocated range
                    // should be sparse.
                    let default_value = match &default_value {
                        Some(default_value) => default_value,
                        None => {
                            // I've read somewhere that the default value for a sparse
                            // file in windows might not be zero. To be safe, we read one
                            // byte before starting writing.
                            let mut val = [0u8];
                            file.read_exact(&mut val)?;
                            file.seek(io::SeekFrom::Start(file_pos))?;

                            default_value = Some([val[0]; 4096]);
                            default_value.as_ref().unwrap()
                        }
                    };

                    // Write the file until the start of the slice:
                    while file_pos < e.FileOffset as u64 {
                        let write_count =
                            min(default_value.len() as u64, e.FileOffset as u64 - file_pos)
                                as usize;
                        file.write_all(&default_value[..write_count])?;
                        file_pos += write_count as u64;
                    }
                    assert_eq!(file_pos, e.FileOffset as u64);
                }

                file_pos = file.seek(io::SeekFrom::Start(file_pos + e.Length as u64))?;
            }

            if success {
                assert_eq!(file_pos, size);
                break;
            } else {
                assert!(file_pos < size);
                // We have more data to process, skip the range we already processed:
                query_range[0] = FILE_ALLOCATED_RANGE_BUFFER {
                    Length: (size - file_pos) as i64,
                    FileOffset: file_pos as i64,
                };
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        env::temp_dir,
        ffi::c_void,
        fs::OpenOptions,
        mem::{size_of_val, MaybeUninit},
        os::windows::prelude::{AsRawHandle, FileExt},
        ptr,
    };

    use windows_sys::Win32::{
        Foundation::HANDLE,
        System::{
            Ioctl::{FILE_ALLOCATED_RANGE_BUFFER, FSCTL_QUERY_ALLOCATED_RANGES, FSCTL_SET_SPARSE},
            IO::DeviceIoControl,
        },
    };

    use crate::platform::windows::{mimic_fallocate, ENTRY_SIZE};

    #[test]
    #[ignore]
    fn test_mimic_fallocate() {
        let path = temp_dir().join("test-sparse-file.bin");
        println!("File path: {path:?}");
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(path)
            .unwrap();

        // Set the file to sparse
        unsafe {
            let mut bytes_returned = 0u32;
            assert!(
                DeviceIoControl(
                    file.as_raw_handle() as HANDLE,
                    FSCTL_SET_SPARSE,
                    ptr::null(),
                    0,
                    ptr::null_mut(),
                    0,
                    &mut bytes_returned,
                    ptr::null_mut(),
                ) != 0
            );
        }

        let size = 50 * 1024 * 1024;
        file.set_len(size).unwrap();

        // Write to 3 equidistant places in the file:
        let write_positions = [size * 1 / 4, size * 2 / 4, size * 3 / 4];
        for pos in write_positions {
            file.seek_write(&[42], pos).unwrap();
        }

        // Ensure the file has only 3 small allocated chunks:
        unsafe {
            let query_range = FILE_ALLOCATED_RANGE_BUFFER {
                FileOffset: 0,
                Length: size as i64,
            };

            let mut ranges: MaybeUninit<[FILE_ALLOCATED_RANGE_BUFFER; 3]> = MaybeUninit::uninit();

            let mut ret_size = 0;
            assert!(
                DeviceIoControl(
                    file.as_raw_handle() as HANDLE,
                    FSCTL_QUERY_ALLOCATED_RANGES,
                    ptr::addr_of!(query_range) as *const c_void,
                    ENTRY_SIZE,
                    ranges.as_mut_ptr() as *mut c_void,
                    size_of_val(&ranges) as u32,
                    &mut ret_size,
                    ptr::null_mut(),
                ) != 0
            );

            assert_eq!(ret_size as usize, size_of_val(&ranges));
            for (r, expected_pos) in ranges.assume_init().into_iter().zip(write_positions) {
                assert!(expected_pos >= r.FileOffset as u64);
                assert!(expected_pos < (r.FileOffset + r.Length) as u64);
                assert!(size > r.Length as u64);
            }
        }

        // Fully allocate space for the file:
        mimic_fallocate(&mut file, size).unwrap();

        // Ensure the file's allocated chunks cover the entire size:
        unsafe {
            let mut cursor = 0u64;
            while cursor < size {
                let query_range = FILE_ALLOCATED_RANGE_BUFFER {
                    FileOffset: cursor as i64,
                    Length: (size - cursor) as i64,
                };

                let mut ranges = [MaybeUninit::<FILE_ALLOCATED_RANGE_BUFFER>::uninit(); 512];

                let mut ret_size = 0;
                assert!(
                    DeviceIoControl(
                        file.as_raw_handle() as HANDLE,
                        FSCTL_QUERY_ALLOCATED_RANGES,
                        ptr::addr_of!(query_range) as *const c_void,
                        ENTRY_SIZE,
                        ranges.as_mut_ptr() as *mut c_void,
                        size_of_val(&ranges) as u32,
                        &mut ret_size,
                        ptr::null_mut(),
                    ) != 0
                );

                assert!(ret_size > 0);
                assert_eq!(ret_size % ENTRY_SIZE, 0);
                let ranges = &ranges[..(ret_size / ENTRY_SIZE) as usize];
                for r in ranges.into_iter().map(|r| r.assume_init_ref()) {
                    assert_eq!(cursor, r.FileOffset as u64);
                    cursor += r.Length as u64;
                }
            }
            assert_eq!(cursor, size);
        }
    }
}
