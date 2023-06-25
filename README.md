This library provides a way to see a group of files as a single addressable byte
array. The files are directly mapped into memory to avoid buffer copies and faster
network send/receive, when leaving data cache management to the OS. The mappings
themselves are cached to prevent frequent system calls.

It was specifically designed for BitTorrent V1 applications, where all the files
in a torrent are seen as a big byte array for hashing and addressing purposes.

## Why?

Usual file operations entails to opening a file, seeking, reading into or
writing from an application memory buffer, as well as processing the data in the
memory buffer before writing or after reading. Often one would also send or
receive the contents of the buffer over the network. Compared to the usual
approach, mapping the file directly offer several pros and a few cons.

### Pros:

 - Less system calls - no more seeking and reading and writing function calls,
   you read and write directly on a buffer managed by the OS. Opening, mapping
   and closing system calls happens on a much coarser frequency and is managed by
   our cache.
 - Less data copy - using read and write system calls, you have to provide a
   buffer where the data is copied to and from the internal OS buffer. Using
   this library, you read or write directly into or from the OS buffer cache,
   with no intermediaries.
 - Less open file descriptors - open file descriptors are a system wide limited
   resource. Using this library, file descriptors are only open for a shot time
   when the file is being mapped. File mappings are a per process resource that
   doesn't interfere with the rest of the system.
 - IO transparently becomes asynchronous - I think this is huge for file ⇔
   network applications. File reads and writes via common system calls are
   synchronous. There are asynchronous APIs, but unless you are a database
   software engineer, you probably never used them. Hardly any of the commonly
   used asynchronous frameworks exposes asynchronous file IO consistently
   (`libuv` can only do asynchronous file IO under Linux if `io_uring` is
   available, `boost::asio` can only do it on Windows, and `tokio`, as of this
   writing, [uses a thread pool for
   it](https://github.com/tokio-rs/tokio/issues/2411)). This means that if you
   have a worker thread in your asynchronous network application read a file and
   then send it via the network, your thread will be blocked while the data is
   retrieved from a possibly slow storage (think of a Raspberry Pi seedbox with
   an USB 2.0 connected hard disk). If instead you send a mapped buffer, even if
   the pages are not loaded into memory, the asynchronous send function returns
   immediately, and actually waiting for the contents of the file becomes a
   problem for the operating system.
 - Better memory management - there is no need to allocate memory for file
   buffers, manage or cache them, it is all handled automatically and
   transparently by the operating system.

### Cons:

 - Harder error handling - on very specific situations, the file is mapped but
   the physical storage space corresponding to some file range is not available.
   Since the file is accessed by reading and writing to a memory address
   directly, the only way for the OS to notify the problem is directly
   interrupting the offending instruction. On POSIX, this means signaling the
   process with SIGBUS. On Windows, this means an exception is raised via the
   Structured Exception Handling mechanism. Both will kill your process if not
   handled, and handling them correctly can be very complicated and error prone,
   specially if you are not using C or C++. That said, the situations this error
   can happen are either too rare, deliberate or can be mitigated, so much that
   I still feel it is OK to not handle the errors and let the process be killed.
   They are:
    - File is sparse and storage is full - this can be avoided by passing `true`
      to `reserve` when opening files for writing. This will allocate all the
      holes in the files before mapping, so that storage is always available. Of
      course, another process or the user might poke holes at the file while in
      use, but that has to be very deliberate to happen.
    - File truncated to a smaller size - if the user or another process truncates
      the file while mapped by your process, a read or write beyond the newly
      truncated size will trigger the error. Again, this has to be deliberate:
      normal file operations the user can perform, like deleting or moving the
      file won't truncate it.
    - There is a hardware error or failure.
 - Misleading memory statistics - at least on Linux, a process that has several
   large mapped files and has recently accessed a lot of different places of
   those files, will show on `top` and other process monitoring tools as using a
   lot of memory. That is because the files' pages cached by the OS will count
   towards the process' shared memory in use. This might be misleading because
   the user might think that the process is holding all those system resources,
   while in reality they are immediately available to any other process that
   needs it. It is like the `buff/cache` column displayed by the `free` command:
   on a long running system, it will be almost always occupying the whole free
   space, while still being available on demand. In fact, a process that access
   a lot file data in the usual way will fill the buffer cache the same way a
   process using this library will fill the shared memory in use, it is just
   that is it not accounted as belonging to that process by the OS.

## Alternatives

For file ⇔ network applications, Linux have functions like `splice()` and
`sendfile()`, that can send the contents of one file descriptor to another.
These functions provides some of the same advantages as this libraries, but they
are platform specific.
