//mod windows;
//mod unix;

#[cfg(unix)]
include!("unix.rs");

#[cfg(windows)]
include!("windows.rs");
