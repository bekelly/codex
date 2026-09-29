use crate::app_package::registered_core_requested;
use crate::app_package::verify_registered_core_runner;
use crate::desktop::DesktopPolicy;
use crate::desktop::shared_private_desktop_for_user;
use crate::desktop_bootstrap::RunnerDesktopBootstrapAccess;
use crate::identity::SandboxCreds;
use crate::ipc_framed::ErrorPayload;
use crate::ipc_framed::ErrorStage;
use crate::ipc_framed::FramedMessage;
use crate::ipc_framed::IPC_PROTOCOL_VERSION;
use crate::ipc_framed::Message;
use crate::ipc_framed::SpawnRequest;
use crate::ipc_framed::read_frame;
use crate::ipc_framed::write_frame;
use crate::logging;
use crate::runner_pipe::PIPE_ACCESS_INBOUND;
use crate::runner_pipe::PIPE_ACCESS_OUTBOUND;
use crate::runner_pipe::connect_pipe;
use crate::runner_pipe::create_named_pipe;
use crate::runner_pipe::find_runner_exe;
use crate::runner_pipe::pipe_set;
use crate::winutil::quote_windows_arg;
use crate::winutil::to_wide;
use anyhow::Context;
use anyhow::Result;
use std::fs::File;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;
use std::os::windows::io::OwnedHandle;
use std::path::Path;
use std::ptr;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use std::time::Instant;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::DUPLICATE_SAME_ACCESS;
use windows_sys::Win32::Foundation::DuplicateHandle;
use windows_sys::Win32::Foundation::ERROR_ACCOUNT_DISABLED;
use windows_sys::Win32::Foundation::ERROR_LOGON_FAILURE;
use windows_sys::Win32::Foundation::ERROR_NO_SUCH_LOGON_SESSION;
use windows_sys::Win32::Foundation::ERROR_NOT_FOUND;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Diagnostics::Debug::SetErrorMode;
use windows_sys::Win32::System::IO::CancelSynchronousIo;
use windows_sys::Win32::System::Pipes::PeekNamedPipe;
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;
use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;
use windows_sys::Win32::System::Threading::CREATE_UNICODE_ENVIRONMENT;
use windows_sys::Win32::System::Threading::CreateProcessWithLogonW;
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::Win32::System::Threading::GetCurrentThread;
use windows_sys::Win32::System::Threading::GetExitCodeProcess;
use windows_sys::Win32::System::Threading::LOGON_WITH_PROFILE;
use windows_sys::Win32::System::Threading::PROCESS_INFORMATION;
use windows_sys::Win32::System::Threading::ResumeThread;
use windows_sys::Win32::System::Threading::STARTF_FORCEOFFFEEDBACK;
use windows_sys::Win32::System::Threading::STARTUPINFOW;
use windows_sys::Win32::System::Threading::TerminateProcess;
use windows_sys::Win32::System::Threading::WaitForSingleObject;

const RUNNER_SPAWN_READY_TIMEOUT: Duration = Duration::from_secs(15);
const RUNNER_PIPE_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const RUNNER_SPAWN_READY_POLL_INTERVAL: Duration = Duration::from_millis(5);
const RUNNER_PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(50);
const RUNNER_TEARDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const RUNNER_ERROR_MODE_FLAGS: u32 = 0x0001 | 0x0002;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 0x0000_0102;

fn runner_startup_diagnostic(message: &str, log_dir: Option<&Path>) {
    logging::log_note(&format!("RUNNER STARTUP: {message}"), log_dir);
}

fn runner_exit_code(process: HANDLE) -> Result<u32> {
    let mut exit_code = 0u32;
    if unsafe { GetExitCodeProcess(process, &mut exit_code) } == 0 {
        anyhow::bail!("GetExitCodeProcess failed for runner: {}", unsafe {
            GetLastError()
        });
    }
    Ok(exit_code)
}

fn format_exit_code(exit_code: u32) -> String {
    format!("0x{exit_code:08X} ({exit_code})")
}

#[derive(Debug)]
struct RunnerLogonError {
    code: u32,
}

impl std::fmt::Display for RunnerLogonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CreateProcessWithLogonW failed: {}", self.code)
    }
}

impl std::error::Error for RunnerLogonError {}

#[derive(Debug)]
pub(crate) struct RunnerStartupError {
    payload: ErrorPayload,
}

impl RunnerStartupError {
    pub(crate) fn new(payload: ErrorPayload) -> Self {
        Self { payload }
    }
}

impl std::fmt::Display for RunnerStartupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "runner failed during {:?}: {}",
            self.payload.stage, self.payload.message
        )?;
        if let Some(code) = self.payload.windows_error_code {
            write!(f, " (Windows error {code})")?;
        }
        Ok(())
    }
}

impl std::error::Error for RunnerStartupError {}

struct OwnedWinHandle(HANDLE);

impl OwnedWinHandle {
    fn new(handle: HANDLE) -> Self {
        Self(handle)
    }

    fn get(&self) -> HANDLE {
        self.0
    }

    fn into_raw(mut self) -> HANDLE {
        let handle = self.0;
        self.0 = 0;
        handle
    }
}

impl Drop for OwnedWinHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

/// Owns a newly created runner until its process and desktop access move into `RunnerLifetime`.
/// Startup failures use the same ordered cleanup as completed sessions.
struct PendingRunner {
    process: OwnedWinHandle,
    thread: Option<OwnedWinHandle>,
    pid: u32,
    terminate_on_drop: bool,
    log_dir: Option<std::path::PathBuf>,
    desktop_access: Option<RunnerDesktopBootstrapAccess>,
}

impl PendingRunner {
    fn new(
        process_information: PROCESS_INFORMATION,
        log_dir: Option<&Path>,
        desktop_access: RunnerDesktopBootstrapAccess,
    ) -> Self {
        Self {
            process: OwnedWinHandle::new(process_information.hProcess),
            thread: Some(OwnedWinHandle::new(process_information.hThread)),
            pid: process_information.dwProcessId,
            terminate_on_drop: true,
            log_dir: log_dir.map(Path::to_path_buf),
            desktop_access: Some(desktop_access),
        }
    }

    fn resume(&mut self) -> Result<()> {
        let thread = self
            .thread
            .as_ref()
            .context("suspended runner thread handle is missing")?;
        if unsafe { ResumeThread(thread.get()) } == u32::MAX {
            anyhow::bail!("ResumeThread(runner) failed: {}", unsafe { GetLastError() });
        }
        self.thread.take();
        Ok(())
    }

    fn into_lifetime(mut self) -> RunnerLifetime {
        self.terminate_on_drop = false;
        let process = std::mem::replace(&mut self.process, OwnedWinHandle::new(0));
        RunnerLifetime {
            process,
            desktop_access: self.desktop_access.take(),
            log_dir: self.log_dir.take(),
        }
    }

    fn abort(mut self, startup_error: anyhow::Error) -> anyhow::Error {
        self.terminate_on_drop = false;
        let Some(desktop_access) = self.desktop_access.take() else {
            return startup_error.context("startup desktop access guard is missing");
        };
        let cleanup_result = cleanup_or_recover(RecoveryResources {
            process: std::mem::replace(&mut self.process, OwnedWinHandle::new(0)),
            desktop_access,
            log_dir: self.log_dir.take(),
        });
        match cleanup_result {
            Ok(()) => startup_error,
            Err(cleanup_error) => anyhow::anyhow!(
                "{startup_error:#}; startup runner cleanup also failed: {cleanup_error:#}"
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RunnerTeardownReason {
    ExitReceived,
    TransportClosed,
}

pub(crate) struct RunnerLifetime {
    process: OwnedWinHandle,
    desktop_access: Option<RunnerDesktopBootstrapAccess>,
    log_dir: Option<std::path::PathBuf>,
}

impl RunnerLifetime {
    pub(crate) fn finish(mut self, reason: RunnerTeardownReason) -> Result<()> {
        let process = self.process.get();
        let desktop_access = self
            .desktop_access
            .as_mut()
            .context("runner desktop access guard is missing")?;
        cleanup_after_runner(
            reason,
            || runner_exited_within(process, RUNNER_TEARDOWN_TIMEOUT),
            || terminate_runner_and_wait(process, RUNNER_TEARDOWN_TIMEOUT),
            || desktop_access.revoke(),
        )
        .context("runner authority cleanup failed")?;
        self.desktop_access.take();
        Ok(())
    }
}

impl Drop for RunnerLifetime {
    fn drop(&mut self) {
        if let Some(desktop_access) = self.desktop_access.take() {
            let _ = cleanup_or_recover(RecoveryResources {
                process: std::mem::replace(&mut self.process, OwnedWinHandle::new(0)),
                desktop_access,
                log_dir: self.log_dir.take(),
            });
        }
    }
}

impl Drop for PendingRunner {
    fn drop(&mut self) {
        if self.terminate_on_drop
            && let Some(desktop_access) = self.desktop_access.take()
        {
            let _ = cleanup_or_recover(RecoveryResources {
                process: std::mem::replace(&mut self.process, OwnedWinHandle::new(0)),
                desktop_access,
                log_dir: self.log_dir.take(),
            });
        }
    }
}

/// Revocation is attempted only after the runner has been observed exiting.
fn cleanup_after_runner(
    reason: RunnerTeardownReason,
    wait_for_exit: impl FnOnce() -> Result<bool>,
    terminate_and_wait: impl FnOnce() -> Result<()>,
    revoke: impl FnOnce() -> Result<()>,
) -> Result<()> {
    match reason {
        RunnerTeardownReason::ExitReceived => {
            if !wait_for_exit()? {
                terminate_and_wait().context("runner remained alive after sending exit")?;
            }
        }
        RunnerTeardownReason::TransportClosed => {
            terminate_and_wait().context("terminate runner after transport closed")?;
        }
    }
    revoke().context("remove runner desktop access after command completion")
}

fn runner_exited_within(process: HANDLE, timeout: Duration) -> Result<bool> {
    let wait = unsafe {
        WaitForSingleObject(
            process,
            u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX),
        )
    };
    match wait {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        _ => anyhow::bail!(
            "WaitForSingleObject failed for runner teardown: {}",
            unsafe { GetLastError() }
        ),
    }
}

struct RecoveryResources {
    process: OwnedWinHandle,
    desktop_access: RunnerDesktopBootstrapAccess,
    log_dir: Option<std::path::PathBuf>,
}

impl RecoveryResources {
    fn cleanup_once(&mut self) -> Result<()> {
        let process = self.process.get();
        cleanup_after_runner(
            RunnerTeardownReason::TransportClosed,
            || runner_exited_within(process, RUNNER_TEARDOWN_TIMEOUT),
            || terminate_runner_and_wait(process, RUNNER_TEARDOWN_TIMEOUT),
            || self.desktop_access.revoke(),
        )
    }

    fn report_failure(&self, err: &anyhow::Error) {
        logging::log_note(
            &format!("RUNNER CLEANUP: process and desktop grants retained for retry: {err:#}"),
            self.log_dir.as_deref(),
        );
    }
}

fn attempt_recovery_cleanup(resources: &mut RecoveryResources) -> Result<()> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| resources.cleanup_once()))
        .map_err(|_| anyhow::anyhow!("runner cleanup panicked; ownership retained for retry"))?
}

static RECOVERY_SENDER: OnceLock<Mutex<Option<mpsc::Sender<RecoveryResources>>>> = OnceLock::new();

fn recovery_sender() -> Result<mpsc::Sender<RecoveryResources>> {
    let state = RECOVERY_SENDER.get_or_init(|| Mutex::new(None));
    let mut sender = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(existing) = sender.as_ref() {
        return Ok(existing.clone());
    }
    let (tx, rx) = mpsc::channel();
    thread::Builder::new()
        .name("codex-runner-cleanup".to_string())
        .spawn(move || recovery_loop(rx))
        .context("start runner cleanup recovery thread")?;
    *sender = Some(tx.clone());
    Ok(tx)
}

fn recovery_loop(receiver: mpsc::Receiver<RecoveryResources>) {
    let mut pending = Vec::<(RecoveryResources, u32)>::new();
    loop {
        match receiver.recv_timeout(Duration::from_secs(1)) {
            Ok(resources) => pending.push((resources, 0)),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) if pending.is_empty() => return,
            Err(mpsc::RecvTimeoutError::Disconnected) => thread::sleep(Duration::from_secs(1)),
        }
        while let Ok(resources) = receiver.try_recv() {
            pending.push((resources, 0));
        }
        let mut index = 0;
        while index < pending.len() {
            let (resources, attempts) = &mut pending[index];
            match attempt_recovery_cleanup(resources) {
                Ok(()) => {
                    pending.swap_remove(index);
                }
                Err(err) => {
                    if *attempts == 0 || *attempts % 60 == 0 {
                        resources.report_failure(&err);
                    }
                    *attempts = attempts.saturating_add(1);
                    index += 1;
                }
            }
        }
    }
}

fn cleanup_or_recover(mut resources: RecoveryResources) -> Result<()> {
    let Err(cleanup_error) = attempt_recovery_cleanup(&mut resources) else {
        return Ok(());
    };
    resources.report_failure(&cleanup_error);
    loop {
        match recovery_sender() {
            Ok(sender) => match sender.send(resources) {
                Ok(()) => return Err(cleanup_error),
                Err(send_error) => {
                    resources = send_error.0;
                    let state = RECOVERY_SENDER.get_or_init(|| Mutex::new(None));
                    *state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
                }
            },
            Err(start_error) => {
                resources.report_failure(&start_error);
                // If a worker cannot start, keep ownership here and retry. Dropping either
                // field now would revoke access before process exit could be established.
                if attempt_recovery_cleanup(&mut resources).is_ok() {
                    return Err(cleanup_error);
                }
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

fn terminate_runner_and_wait(process: HANDLE, timeout: Duration) -> Result<()> {
    let wait = unsafe { WaitForSingleObject(process, 0) };
    if wait == WAIT_OBJECT_0 {
        return Ok(());
    }
    if wait != WAIT_TIMEOUT {
        anyhow::bail!(
            "WaitForSingleObject failed before runner termination: {}",
            unsafe { GetLastError() }
        );
    }
    if unsafe {
        TerminateProcess(process, /*uexitcode*/ 1)
    } == 0
    {
        anyhow::bail!("TerminateProcess(runner) failed: {}", unsafe {
            GetLastError()
        });
    }
    let wait = unsafe {
        WaitForSingleObject(
            process,
            u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX),
        )
    };
    anyhow::ensure!(
        wait == WAIT_OBJECT_0,
        "runner did not exit after termination (wait result {wait})"
    );
    Ok(())
}

pub(crate) struct RunnerTransport {
    pipe_write: File,
    pipe_read: File,
    lifetime: RunnerLifetime,
}

fn is_refreshable_windows_error(code: u32) -> bool {
    matches!(
        code,
        ERROR_ACCOUNT_DISABLED | ERROR_LOGON_FAILURE | ERROR_NO_SUCH_LOGON_SESSION
    )
}

fn command_targets_windows_apps(command: &[String]) -> bool {
    command.first().is_some_and(|program| {
        Path::new(program).components().any(|component| {
            component
                .as_os_str()
                .to_string_lossy()
                .eq_ignore_ascii_case("WindowsApps")
        })
    })
}

pub(crate) fn is_refreshable_sandbox_creds_error(err: &anyhow::Error, command: &[String]) -> bool {
    if err
        .downcast_ref::<RunnerLogonError>()
        .is_some_and(|err| is_refreshable_windows_error(err.code))
    {
        return true;
    }

    err.downcast_ref::<RunnerStartupError>().is_some_and(|err| {
        err.payload.stage == ErrorStage::SpawnChild
            && err.payload.windows_error_code.is_some_and(|code| {
                // AppX activation can return 1312 for a healthy sandbox token. Rotating the
                // account password cannot make the same WindowsApps command launch.
                is_refreshable_windows_error(code)
                    && (code != ERROR_NO_SUCH_LOGON_SESSION
                        || !command_targets_windows_apps(command))
            })
    })
}

pub(crate) fn retry_runner_spawn_once<T>(
    sandbox_creds: SandboxCreds,
    command: &[String],
    mut spawn: impl FnMut(SandboxCreds) -> Result<T>,
    refresh: impl FnOnce() -> Result<SandboxCreds>,
) -> Result<T> {
    let result = match spawn(sandbox_creds) {
        Ok(result) => Ok(result),
        Err(err) if is_refreshable_sandbox_creds_error(&err, command) => refresh().and_then(spawn),
        Err(err) => Err(err),
    };
    super::runner_metrics::record("startup", if result.is_ok() { "success" } else { "error" });
    result
}

impl RunnerTransport {
    pub(crate) fn send_spawn_request(&mut self, request: SpawnRequest) -> Result<()> {
        let spawn_request = FramedMessage {
            version: IPC_PROTOCOL_VERSION,
            message: Message::SpawnRequest {
                payload: Box::new(request),
            },
        };
        write_frame(&mut self.pipe_write, &spawn_request)
    }

    pub(crate) fn read_spawn_ready(&mut self) -> Result<()> {
        crate::framed_io::wait_for_complete_frame(
            &self.pipe_read,
            Instant::now() + RUNNER_SPAWN_READY_TIMEOUT,
        )
        .context("wait for runner spawn_ready")?;
        let msg = read_frame(&mut self.pipe_read)?
            .ok_or_else(|| anyhow::anyhow!("runner pipe closed before spawn_ready"))?;
        match msg.message {
            Message::SpawnReady { .. } => Ok(()),
            Message::Error { payload } => Err(RunnerStartupError::new(payload).into()),
            other => Err(anyhow::anyhow!(
                "expected spawn_ready from runner, got {other:?}"
            )),
        }
    }

    pub(crate) fn into_parts(self) -> (File, File, RunnerLifetime) {
        (self.pipe_write, self.pipe_read, self.lifetime)
    }
}

fn try_take_completed_connect_result(
    connect_thread: &mut Option<thread::JoinHandle<()>>,
    connect_result_rx: &mpsc::Receiver<Result<()>>,
    thread_handle: HANDLE,
    pipe_label: &str,
) -> Result<Option<Result<()>>> {
    let thread_wait = unsafe { WaitForSingleObject(thread_handle, 0) };
    if thread_wait != WAIT_OBJECT_0 {
        return Ok(None);
    }

    if let Some(connect_thread) = connect_thread.take() {
        let _ = connect_thread.join();
    }

    let result = connect_result_rx.recv().map_err(|_| {
        anyhow::anyhow!("runner {pipe_label} connect thread exited before reporting its result")
    })?;
    Ok(Some(result))
}

fn connect_pipe_with_timeout(
    h_pipe: HANDLE,
    expected_runner_pid: u32,
    runner_process: HANDLE,
    pipe_label: &str,
    log_dir: Option<&Path>,
) -> Result<()> {
    let pipe_label = pipe_label.to_string();
    let pipe_label_for_thread = pipe_label.clone();
    let (thread_handle_tx, thread_handle_rx) = mpsc::sync_channel(1);
    let (connect_result_tx, connect_result_rx) = mpsc::sync_channel(1);
    let mut connect_thread = Some(
        thread::Builder::new()
            .name(format!("codex-runner-connect-{pipe_label}"))
            .spawn(move || {
                let current_process = unsafe { GetCurrentProcess() };
                let mut thread_handle = 0;
                let duplicate_ok = unsafe {
                    DuplicateHandle(
                        current_process,
                        GetCurrentThread(),
                        current_process,
                        &mut thread_handle,
                        /*dwdesiredaccess*/ 0,
                        /*binherithandle*/ 0,
                        DUPLICATE_SAME_ACCESS,
                    )
                };
                if duplicate_ok == 0 {
                    let _ = thread_handle_tx.send(Err(anyhow::anyhow!(
                        "DuplicateHandle failed for runner {pipe_label_for_thread} connect thread: {}",
                        unsafe { GetLastError() }
                    )));
                    return;
                }

                // Publish the helper thread HANDLE before the blocking pipe connect so the
                // parent can cancel this specific operation if it times out.
                let _ = thread_handle_tx.send(Ok(thread_handle));

                let result = connect_pipe(h_pipe, expected_runner_pid)
                    .map_err(anyhow::Error::from)
                    .context(format!("connect {pipe_label_for_thread}"));
                let _ = connect_result_tx.send(result);
            })?,
    );
    let thread_handle = thread_handle_rx.recv().map_err(|_| {
        anyhow::anyhow!("runner {pipe_label} connect thread exited before publishing its handle")
    })??;

    let deadline = Instant::now() + RUNNER_PIPE_CONNECT_TIMEOUT;
    let result = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let poll_interval = remaining.min(RUNNER_PROCESS_POLL_INTERVAL);
        match connect_result_rx.recv_timeout(poll_interval) {
            Ok(result) => {
                if let Some(connect_thread) = connect_thread.take() {
                    let _ = connect_thread.join();
                }
                break result;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if let Some(connect_thread) = connect_thread.take() {
                    let _ = connect_thread.join();
                }
                break Err(anyhow::anyhow!(
                    "runner {pipe_label} connect thread exited before reporting its result"
                ));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }

        let completed_connect = try_take_completed_connect_result(
            &mut connect_thread,
            &connect_result_rx,
            thread_handle,
            &pipe_label,
        );
        match completed_connect {
            Ok(Some(result)) => break result,
            Ok(None) => {}
            Err(err) => break Err(err),
        }

        let process_wait = unsafe { WaitForSingleObject(runner_process, 0) };
        if process_wait == WAIT_OBJECT_0 {
            let exit_code = match runner_exit_code(runner_process) {
                Ok(exit_code) => exit_code,
                Err(err) => break Err(err),
            };
            runner_startup_diagnostic(
                &format!(
                    "runner pid={expected_runner_pid} exited before {pipe_label} connected; exit_code={}",
                    format_exit_code(exit_code)
                ),
                log_dir,
            );
            let _ = unsafe { CancelSynchronousIo(thread_handle) };
            break Err(anyhow::anyhow!(
                "runner exited before connecting {pipe_label} with Windows process exit code {}",
                format_exit_code(exit_code)
            ));
        }
        if process_wait != WAIT_TIMEOUT {
            break Err(anyhow::anyhow!(
                "WaitForSingleObject failed while monitoring runner {pipe_label}: {}",
                unsafe { GetLastError() }
            ));
        }

        if Instant::now() >= deadline {
            runner_startup_diagnostic(
                &format!(
                    "timed out after {}ms connecting {pipe_label}; runner pid={expected_runner_pid} alive=true",
                    RUNNER_PIPE_CONNECT_TIMEOUT.as_millis()
                ),
                log_dir,
            );
            let cancel_ok = unsafe { CancelSynchronousIo(thread_handle) };
            if cancel_ok == 0 {
                let err = unsafe { GetLastError() };
                if err != ERROR_NOT_FOUND {
                    break Err(anyhow::anyhow!(
                        "CancelSynchronousIo failed for runner {pipe_label} connect thread: {err}"
                    ));
                }
                let completed_connect = try_take_completed_connect_result(
                    &mut connect_thread,
                    &connect_result_rx,
                    thread_handle,
                    &pipe_label,
                );
                match completed_connect {
                    Ok(Some(result)) => break result,
                    Ok(None) => {}
                    Err(err) => break Err(err),
                }
            }
            // Do not join the helper thread on the timeout path. Parent-side cleanup will close
            // the pipe handle, which lets the blocked connect unwind without another indefinite
            // wait here.
            break Err(anyhow::anyhow!(
                "timed out after {}ms connecting runner {pipe_label}; runner process was still alive",
                RUNNER_PIPE_CONNECT_TIMEOUT.as_millis()
            ));
        }
    };

    unsafe {
        CloseHandle(thread_handle);
    }

    result
}

pub(crate) fn spawn_runner_transport(
    codex_home: &Path,
    cwd: &Path,
    sandbox_creds: &SandboxCreds,
    log_dir: Option<&Path>,
    mut spawn_request: SpawnRequest,
    desktop_policy: Option<&DesktopPolicy>,
) -> Result<RunnerTransport> {
    let runner_exe = find_runner_exe(codex_home, log_dir)?;
    let registered_alias = if registered_core_requested() {
        Some(crate::app_package::registered_runner_alias(
            codex_home,
            &sandbox_creds.username,
        )?)
    } else {
        None
    };
    if let Some(policy) = desktop_policy {
        spawn_request.private_desktop_name = Some(shared_private_desktop_for_user(
            &sandbox_creds.username,
            policy,
            log_dir,
        )?);
    }
    let (startup_pipe_name, pipe_in_name, pipe_out_name) = pipe_set();
    let startup_pipe = OwnedWinHandle::new(create_named_pipe(
        &startup_pipe_name,
        PIPE_ACCESS_INBOUND,
        &sandbox_creds.username,
    )?);
    let pipe_in = OwnedWinHandle::new(create_named_pipe(
        &pipe_in_name,
        PIPE_ACCESS_OUTBOUND,
        &sandbox_creds.username,
    )?);
    let pipe_out = OwnedWinHandle::new(create_named_pipe(
        &pipe_out_name,
        PIPE_ACCESS_INBOUND,
        &sandbox_creds.username,
    )?);

    let runner_cmdline = registered_alias
        .as_deref()
        .unwrap_or(&runner_exe)
        .to_str()
        .map(str::to_owned)
        .unwrap_or_else(|| "codex-command-runner.exe".to_string());
    let runner_full_cmd = format!(
        "{} {} {} {}",
        quote_windows_arg(&runner_cmdline),
        quote_windows_arg(&format!("--startup-pipe={startup_pipe_name}")),
        quote_windows_arg(&format!("--pipe-in={pipe_in_name}")),
        quote_windows_arg(&format!("--pipe-out={pipe_out_name}"))
    );
    let mut cmdline_vec = to_wide(&runner_full_cmd);
    let exe_w = to_wide(&runner_cmdline);
    let cwd_w = to_wide(cwd);
    let user_w = to_wide(&sandbox_creds.username);
    let domain_w = to_wide(".");
    let password_w = to_wide(&sandbox_creds.password);
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    si.dwFlags = STARTF_FORCEOFFFEEDBACK;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let bootstrap_access = RunnerDesktopBootstrapAccess::new(log_dir);
    let previous_error_mode = unsafe { SetErrorMode(RUNNER_ERROR_MODE_FLAGS) };
    // Execution aliases require the registered account's profile.
    // Other launches retain their existing profile-free behavior.
    let spawn_res = unsafe {
        CreateProcessWithLogonW(
            user_w.as_ptr(),
            domain_w.as_ptr(),
            password_w.as_ptr(),
            if registered_alias.is_some() {
                LOGON_WITH_PROFILE
            } else {
                0
            },
            exe_w.as_ptr(),
            cmdline_vec.as_mut_ptr(),
            CREATE_NO_WINDOW | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
            ptr::null(),
            cwd_w.as_ptr(),
            &si,
            &mut pi,
        )
    };
    let spawn_error = (spawn_res == 0).then(|| unsafe { GetLastError() });
    unsafe {
        SetErrorMode(previous_error_mode);
    }
    if let Some(err) = spawn_error {
        return Err(RunnerLogonError { code: err }.into());
    }
    let mut runner = PendingRunner::new(pi, log_dir, bootstrap_access);
    let startup_result = (|| -> Result<()> {
        // Verify the selected AppX image while the process is suspended.
        if registered_alias.is_some() {
            verify_registered_core_runner(runner.process.get(), &runner_exe)?;
        }
        let process = runner.process.get();
        runner
            .desktop_access
            .as_mut()
            .context("suspended runner desktop access guard is missing")?
            .grant_child_logon_sid(process)
            .context("grant suspended runner logon-SID desktop access")?;
        runner.resume()
    })();
    if let Err(err) = startup_result {
        return Err(runner.abort(err));
    }
    let expected_runner_pid = runner.pid;
    // From this point onward, every error path must stop the running helper before revoking the
    // logon-SID access that it and its restricted command child share.
    let lifetime = runner.into_lifetime();

    connect_pipe_with_timeout(
        startup_pipe.get(),
        expected_runner_pid,
        lifetime.process.get(),
        "startup-marker",
        log_dir,
    )?;
    drop(startup_pipe);
    connect_pipe_with_timeout(
        pipe_in.get(),
        expected_runner_pid,
        lifetime.process.get(),
        "pipe-in",
        log_dir,
    )?;
    connect_pipe_with_timeout(
        pipe_out.get(),
        expected_runner_pid,
        lifetime.process.get(),
        "pipe-out",
        log_dir,
    )?;

    let pipe_write = unsafe { File::from_raw_handle(pipe_in.into_raw() as _) };
    let pipe_read = unsafe { File::from_raw_handle(pipe_out.into_raw() as _) };
    let mut transport = RunnerTransport {
        // Once the pipe connect phase succeeds we can transfer the raw HANDLEs into `File`s.
        // From here on, the `RunnerTransport` owns closing the pipes on every success/error path.
        pipe_write,
        pipe_read,
        lifetime,
    };
    transport.send_spawn_request(spawn_request)?;
    transport.read_spawn_ready()?;
    if registered_alias.is_some() {
        crate::logging::debug_log(
            &format!(
                "registered_core_runner_ready pid={expected_runner_pid} package_verified=true pipes_authenticated=true"
            ),
            log_dir,
        );
    }

    Ok(transport)
}

#[cfg(test)]
mod tests {
    use super::RunnerLogonError;
    use super::RunnerStartupError;
    use super::RunnerTeardownReason;
    use super::cleanup_after_runner;
    use super::connect_pipe_with_timeout;
    use super::is_refreshable_sandbox_creds_error;
    use crate::ipc_framed::ErrorPayload;
    use crate::ipc_framed::ErrorStage;
    use crate::runner_pipe::PIPE_ACCESS_INBOUND;
    use crate::runner_pipe::create_named_pipe;
    use pretty_assertions::assert_eq;
    use std::cell::RefCell;
    use std::os::windows::io::AsRawHandle;
    use std::process::Command;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Foundation::ERROR_ACCOUNT_DISABLED;
    use windows_sys::Win32::Foundation::ERROR_LOGON_FAILURE;
    use windows_sys::Win32::Foundation::ERROR_NO_SUCH_LOGON_SESSION;
    use windows_sys::Win32::Foundation::ERROR_NOT_FOUND;

    #[test]
    fn termination_failure_retains_grants_for_a_later_cleanup_attempt() {
        let steps = RefCell::new(Vec::new());
        let first = cleanup_after_runner(
            RunnerTeardownReason::TransportClosed,
            || panic!("transport closure does not wait for a graceful exit"),
            || {
                steps.borrow_mut().push("terminate failed");
                anyhow::bail!("termination failed")
            },
            || {
                steps.borrow_mut().push("revoke");
                Ok(())
            },
        );
        assert!(first.unwrap_err().to_string().contains("terminate runner"));
        assert_eq!(*steps.borrow(), ["terminate failed"]);

        cleanup_after_runner(
            RunnerTeardownReason::TransportClosed,
            || panic!("transport closure does not wait for a graceful exit"),
            || {
                steps.borrow_mut().push("terminated on retry");
                Ok(())
            },
            || {
                steps.borrow_mut().push("revoke");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            *steps.borrow(),
            ["terminate failed", "terminated on retry", "revoke"]
        );
    }

    #[test]
    fn wait_timeout_does_not_revoke_when_forced_termination_is_unconfirmed() {
        let steps = RefCell::new(Vec::new());
        let result = cleanup_after_runner(
            RunnerTeardownReason::ExitReceived,
            || {
                steps.borrow_mut().push("wait timed out");
                Ok(false)
            },
            || {
                steps.borrow_mut().push("termination wait timed out");
                anyhow::bail!("runner did not exit after termination")
            },
            || {
                steps.borrow_mut().push("revoke");
                Ok(())
            },
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("runner remained alive")
        );
        assert_eq!(
            *steps.borrow(),
            ["wait timed out", "termination wait timed out"]
        );
    }

    #[test]
    fn confirmed_runner_exit_revokes_without_forced_termination() -> anyhow::Result<()> {
        let steps = RefCell::new(Vec::new());
        cleanup_after_runner(
            RunnerTeardownReason::ExitReceived,
            || {
                steps.borrow_mut().push("exit confirmed");
                Ok(true)
            },
            || panic!("confirmed exit must not force termination"),
            || {
                steps.borrow_mut().push("revoke");
                Ok(())
            },
        )?;
        assert_eq!(*steps.borrow(), ["exit confirmed", "revoke"]);
        Ok(())
    }

    #[test]
    fn refreshable_sandbox_creds_error_recognizes_credential_and_child_start_failures() {
        assert_eq!(
            [
                ERROR_ACCOUNT_DISABLED,
                ERROR_LOGON_FAILURE,
                ERROR_NO_SUCH_LOGON_SESSION,
                ERROR_NOT_FOUND,
            ]
            .map(|code| {
                let err =
                    anyhow::Error::new(RunnerLogonError { code }).context("runner launch failed");
                is_refreshable_sandbox_creds_error(&err, &[])
            }),
            [true, true, true, false]
        );

        assert_eq!(
            [
                (ErrorStage::SpawnChild, ERROR_NO_SUCH_LOGON_SESSION),
                (ErrorStage::SpawnChild, ERROR_NOT_FOUND),
                (ErrorStage::ReadSpawnRequest, ERROR_NO_SUCH_LOGON_SESSION),
            ]
            .map(|(stage, windows_error_code)| {
                let err = anyhow::Error::new(RunnerStartupError::new(ErrorPayload {
                    message: "runner startup failed".to_string(),
                    stage,
                    windows_error_code: Some(windows_error_code),
                }));
                is_refreshable_sandbox_creds_error(&err, &["cmd.exe".to_string()])
            }),
            [true, false, false]
        );

        let windows_apps_commands = [
            vec![
                r"C:\Users\user\AppData\Local\Microsoft\WindowsApps\pwsh.exe".to_string(),
            ],
            vec![
                r"C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.3.0_x64__8wekyb3d8bbwe\pwsh.exe"
                    .to_string(),
            ],
        ];
        assert_eq!(
            windows_apps_commands.map(|command| {
                let err = anyhow::Error::new(RunnerStartupError::new(ErrorPayload {
                    message: "runner startup failed".to_string(),
                    stage: ErrorStage::SpawnChild,
                    windows_error_code: Some(ERROR_NO_SUCH_LOGON_SESSION),
                }));
                is_refreshable_sandbox_creds_error(&err, &command)
            }),
            [false, false]
        );
    }

    #[test]
    fn pipe_connect_reports_runner_exit_code_without_waiting_for_timeout() -> anyhow::Result<()> {
        let username = std::env::var("USERNAME")?;
        let pipe_name = format!(r"\\.\pipe\codex-runner-exit-test-{}", std::process::id());
        let pipe = create_named_pipe(&pipe_name, PIPE_ACCESS_INBOUND, &username)?;
        let mut child = Command::new("cmd.exe")
            .args(["/d", "/c", "exit", "66"])
            .spawn()?;

        let result = connect_pipe_with_timeout(
            pipe,
            child.id(),
            child.as_raw_handle() as _,
            "test-pipe",
            None,
        );
        unsafe {
            CloseHandle(pipe);
        }
        let _ = child.wait();

        assert_eq!(
            result.unwrap_err().to_string(),
            "runner exited before connecting test-pipe with Windows process exit code 0x00000042 (66)"
        );
        Ok(())
    }
}
