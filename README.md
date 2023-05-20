This library provides a way to see a group of files as a single addressable byte
array. They are directly mapped into memory to avoid buffer copies and faster
network send/receive, when leaving data cache management to the OS. The mappings
themselves are cached to prevent frequent system calls.

It was specifically designed for BitTorrent V1 applications, where all the files
in a torrent are seen as a big byte array for hashing and addressing purposes.
