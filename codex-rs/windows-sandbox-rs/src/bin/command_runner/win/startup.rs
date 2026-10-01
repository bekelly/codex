use super::OwnedWinHandle;
use super::open_pipe;
use super::read_spawn_request;
use super::send_error;
use anyhow::Context;
use anyhow::Result;
use codex_windows_sandbox::ErrorStage;
use codex_windows_sandbox::SpawnRequest;
use std::fs::File;
use std::os::windows::io::FromRawHandle;
use std::sync::Arc;
use std::sync::Mutex;
use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ;
use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_WRITE;

#[cfg(test)]
#[path = "startup_tests.rs"]
mod tests;

pub(super) fn connect_and_read_spawn_request(
    startup_pipe: &str,
    pipe_in: &str,
    pipe_out: &str,
) -> Result<(File, Arc<Mutex<File>>, SpawnRequest)> {
    // The marker is the first substantive action after argument parsing, before user32 startup.
    // CreateFileW can open all three pipes before the parent calls ConnectNamedPipe on any of
    // them. Retain the marker until the spawn request acknowledges that the parent connected
    // and verified every pipe; closing it after the transport opens races a delayed parent.
    let startup_marker = OwnedWinHandle::new(
        open_pipe(startup_pipe, FILE_GENERIC_WRITE).context("runner: open startup marker pipe")?,
    );
    let h_pipe_in = OwnedWinHandle::new(open_pipe(pipe_in, FILE_GENERIC_READ)?);
    let h_pipe_out = OwnedWinHandle::new(open_pipe(pipe_out, FILE_GENERIC_WRITE)?);
    let mut pipe_read = unsafe { File::from_raw_handle(h_pipe_in.into_raw() as _) };
    let pipe_write = Arc::new(Mutex::new(unsafe {
        File::from_raw_handle(h_pipe_out.into_raw() as _)
    }));
    let req = match read_spawn_request(&mut pipe_read) {
        Ok(req) => req,
        Err(err) => {
            let _ = send_error(
                &pipe_write,
                ErrorStage::ReadSpawnRequest,
                /*windows_error_code*/ None,
                err.to_string(),
            );
            return Err(err);
        }
    };
    drop(startup_marker);
    Ok((pipe_read, pipe_write, req))
}
