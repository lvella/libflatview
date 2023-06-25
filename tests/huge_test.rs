use std::{
    cmp::min,
    fmt::Display,
    hash::Hasher,
    io::{Cursor, Write},
    path::PathBuf,
    sync::{atomic::AtomicU64, Arc},
    thread::{self},
};

use libflatview::{cache::Cache, FileGroup, Mode};
use rand::{
    distributions::{Alphanumeric, DistString},
    seq::SliceRandom,
    Rng,
};
use rand_distr::{Distribution, LogNormal};
use rand_pcg::Pcg64Mcg;
use tempfile::Builder;

const KB: u64 = 1024;
const MB: u64 = 1024 * KB;
const GB: u64 = 1024 * MB;

struct FileSize(u64);

impl Display for FileSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0 > GB {
            f.write_fmt(format_args!("{:.2} GB", self.0 as f64 / GB as f64))
        } else if self.0 > MB {
            f.write_fmt(format_args!("{:.2} MB", self.0 as f64 / MB as f64))
        } else if self.0 > KB {
            f.write_fmt(format_args!("{:.2} KB", self.0 as f64 / KB as f64))
        } else {
            f.write_fmt(format_args!("{} B", self.0))
        }
    }
}

/// Deterministically generate the content of the test files.
fn get_bytes(from_idx: u64, buffer: &mut [u8]) {
    // Work on sets of 8 bytes:
    let start = from_idx / 8;
    let mut offset = (from_idx % 8) as usize;

    let mut cursor = Cursor::new(buffer);

    for i in start.. {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        hasher.write_u64(i);
        let bytes: [u8; 8] = hasher.finish().to_le_bytes();
        if cursor.write(&bytes[offset..]).unwrap() == 0 {
            break;
        }
        // offset is only used in the first iteration:
        offset = 0;
    }
}

/// Defined randomly the sizes and names of 128 files, except for the first
/// file in the list, that has 5 GB.
fn random_files_and_sizes(dir: PathBuf, mut rng: &mut impl Rng) -> (Vec<(PathBuf, u64)>, u64) {
    let name_distr = Alphanumeric;

    // Generate random directories:
    let mut dirs = vec![dir];
    while dirs.len() < 16 {
        let parent = dirs.choose(rng).unwrap();
        let name = name_distr.sample_string(rng, 12);
        dirs.push(parent.join(name));
    }

    // Defined randomly the size of 128 files, except for one that has 5 GB.
    let mut sizes = vec![5u64 * GB];
    let mut total_size = sizes[0];
    {
        let distr = LogNormal::new(10.5, 4.0).unwrap();
        while sizes.len() < 128 {
            let size = distr.sample(&mut rng) as u64;
            total_size += size;
            sizes.push(size);
        }
    }
    sizes[1..].shuffle(&mut rng);
    println!("total size used: {}", FileSize(total_size));

    // Name the files.
    let files_and_sizes = sizes
        .into_iter()
        .map(|size| {
            let parent = dirs.choose(rng).unwrap();
            let name = name_distr.sample_string(rng, 12);
            (parent.join(name), size)
        })
        .collect::<Vec<_>>();

    for (f, s) in files_and_sizes.iter() {
        println!("{}: {}", f.to_string_lossy(), FileSize(*s));
    }

    (files_and_sizes, total_size)
}

mod multiconsumer {
    use std::sync::atomic::AtomicUsize;

    pub struct Queue<T> {
        counter: AtomicUsize,
        data: Vec<T>,
    }

    impl<T> Queue<T> {
        pub fn new(data: Vec<T>) -> Self {
            Self {
                counter: AtomicUsize::new(0),
                data,
            }
        }

        pub fn next(&self) -> Option<&T> {
            let idx = self
                .counter
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            self.data.get(idx)
        }
    }
}

#[test]
fn write_and_read_big() {
    // Get a temporary directory to perform the test
    let dir = Builder::new().prefix("libflatview-test").tempdir().unwrap();

    // Get an Rng with a known seed
    let rng_seed = 0xcafef00dd15ea5e5;
    let mut rng = Pcg64Mcg::new(rng_seed);

    // Get the file tree:
    let (files, total_size) = random_files_and_sizes(dir.path().to_owned(), &mut rng);

    // Write all the files.
    let cache = Arc::new(Cache::default());
    {
        // we can't have writes much bigger than a few times the maximum slice,
        // otherwise we exhaust the memory address in 32 bits. Limit to 3
        // times the mapping size.
        let max_write = 3 * cache.get_options().max_mapping_size as u64;

        // Split total_size in write chunks. In 64 bits systems, first write is
        // more than 4 GB long inside the same file, to test the Windows 64 bits
        // breakup of a single mapping into multiples of IoSlices.
        let mut writes = vec![0..min(4 * GB + 10 * MB, max_write)];
        {
            let distr = LogNormal::new(10.0, 5.0).unwrap();
            let mut written = writes.last().unwrap().end;
            while written < total_size {
                let len = distr.sample(&mut rng);
                if len <= 0.0 {
                    continue;
                }
                let len = min(len as u64, max_write);
                let end = min(written + len, total_size);
                writes.push(written..end);
                written = end;
            }
        }
        writes.shuffle(&mut rng);
        let writes = multiconsumer::Queue::new(writes);

        // Create the linear accessor to the files:
        let file_group = FileGroup::new(
            cache.clone(),
            &files,
            Mode::ReadWrite {
                reserve: true,
                truncate: true,
            },
            true,
        )
        .unwrap();

        // Execute the writes in parallel threads.
        thread::scope(|s| {
            let writes = &writes;
            let file_group = &file_group;
            for t in 0..8 {
                s.spawn(move || {
                    while let Some(r) = writes.next() {
                        let full_len = r.end - r.start;
                        let mut slices =
                            unsafe { file_group.borrow_mut_unchecked(r.clone()).unwrap() };
                        let slices = slices.get();

                        println!(
                            "Thread {t}: writing {} starting from {}, using {} slices",
                            FileSize(full_len),
                            r.start,
                            slices.len()
                        );

                        let mut idx = r.start;
                        for s in slices {
                            assert!(s.len() as u64 <= full_len);
                            get_bytes(idx, s);
                            idx += s.len() as u64;
                        }
                    }
                });
            }
        });
        println!("Writing done!")
    }

    // Verify what has been written
    {
        let file_group = FileGroup::new(cache, &files, Mode::ReadOnly, true).unwrap();

        // Parallel verify in chunks of 16 KB:
        const CHUNK_SIZE: u64 = 16 * KB;
        let piece_counter = AtomicU64::new(0);
        thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| {
                    let mut chunk_start;
                    while {
                        chunk_start = piece_counter
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                            * CHUNK_SIZE;
                        chunk_start < total_size
                    } {
                        let chunk_size = min(CHUNK_SIZE, total_size - chunk_start);

                        // Calculate the reference value for the chunk.
                        let mut expected = [0u8; CHUNK_SIZE as usize];
                        get_bytes(chunk_start, &mut expected[..chunk_size as usize]);

                        let chunk = file_group
                            .borrow(chunk_start..(chunk_start + chunk_size))
                            .unwrap();
                        let mut curr_byte = 0;
                        for s in chunk.get() {
                            let end = curr_byte + s.len();
                            assert_eq!(&s[..], &expected[curr_byte..end]);
                            curr_byte = end;
                        }
                        assert_eq!(curr_byte as u64, chunk_size);
                    }
                });
            }
        });
        println!("Reading done!");
    }
}
