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
    Foundation::{GetLastError, ERROR_MORE_DATA, HANDLE},
    System::{
        Ioctl::{FILE_ALLOCATED_RANGE_BUFFER, FSCTL_QUERY_ALLOCATED_RANGES},
        SystemInformation::{GetSystemInfo, SYSTEM_INFO},
        IO::DeviceIoControl,
    },
};

lazy_static! {
    /// The page size.
    pub static ref PAGESIZE: u64 = {
        let page = unsafe {
            let mut system_info = MaybeUninit::<SYSTEM_INFO>::uninit();
            GetSystemInfo(system_info.as_mut_ptr());
            system_info.assume_init().dwPageSize as u64
        };
        // Assert a page is a power of two (kinda silly, I know)
        assert!(is_power_of_two(page));
        page
    };
}

pub fn preallocate_file(file: &mut File, size: u64) -> Result<(), Error> {
    const ENTRY_SIZE: u32 = std::mem::size_of::<FILE_ALLOCATED_RANGE_BUFFER>() as u32;

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
                query_range.as_mut_ptr() as *mut c_void,
                ENTRY_SIZE,
                allocated_slices.as_mut_ptr() as *mut c_void,
                // Leave room in the output array so we can fill a dummy EOF
                // entry, so the loop will stop.
                ENTRY_SIZE * (allocated_slices.len() as u32 - 1),
                &mut actual_size,
                ptr::null_mut(),
            ) != 0;

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
            } else {
                let error = GetLastError();
                if error != ERROR_MORE_DATA {
                    return Err(io::Error::from_raw_os_error(error as i32).into());
                }
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
