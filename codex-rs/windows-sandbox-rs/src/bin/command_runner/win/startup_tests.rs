use super::connect_and_read_spawn_request;
use codex_protocol::models::PermissionProfile;
use codex_windows_sandbox::FramedMessage;
use codex_windows_sandbox::IPC_PROTOCOL_VERSION;
use codex_windows_sandbox::Message;
use codex_windows_sandbox::SpawnRequest;
use codex_windows_sandbox::to_wide;
use codex_windows_sandbox::write_frame;
use pretty_assertions::assert_eq;
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::SmallRng;
use std::fs::File;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;
use std::ptr;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use std::time::Instant;
use windows_sys::Win32::Foundation::ERROR_BROKEN_PIPE;
use windows_sys::Win32::Foundation::ERROR_NO_DATA;
use windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::Pipes::ConnectNamedPipe;
use windows_sys::Win32::System::Pipes::CreateNamedPipeW;
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::Pipes::PeekNamedPipe;

struct Launch {
    marker: File,
    input: File,
    output: File,
    result: mpsc::Receiver<anyhow::Result<SpawnRequest>>,
}

impl Launch {
    fn start() -> anyhow::Result<Self> {
        let nonce: u128 = SmallRng::from_entropy().r#gen();
        let base = format!(r"\\.\pipe\codex-startup-test-{nonce:x}");
        let names = [
            format!("{base}-startup"),
            format!("{base}-in"),
            format!("{base}-out"),
        ];
        let mut pipes = Vec::new();
        for (name, access) in names.iter().zip([1, 2, 1]) {
            // Grant only the pipe owner access, including when the test user is not an admin.
            let mut descriptor = ptr::null_mut();
            let converted = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    to_wide("D:(A;;GA;;;OW)").as_ptr(),
                    /*stringsdrevision*/ 1,
                    &mut descriptor,
                    ptr::null_mut(),
                )
            };
            anyhow::ensure!(converted != 0, "create test pipe security descriptor");
            let security = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            };
            let handle = unsafe {
                CreateNamedPipeW(
                    to_wide(name).as_ptr(),
                    access,
                    /*dwpipemode*/ 0,
                    /*nmaxinstances*/ 1,
                    /*noutbuffersize*/ 65536,
                    /*ninbuffersize*/ 65536,
                    /*ndefaulttimeout*/ 0,
                    &security,
                )
            };
            let error = unsafe { GetLastError() };
            unsafe {
                LocalFree(descriptor as _);
            }
            anyhow::ensure!(handle != INVALID_HANDLE_VALUE, "create test pipe: {error}");
            pipes.push(unsafe { File::from_raw_handle(handle as _) });
        }
        let (tx, result) = mpsc::channel();
        thread::spawn(move || {
            let result = connect_and_read_spawn_request(&names[0], &names[1], &names[2])
                .map(|(_reader, _writer, request)| request);
            let _ = tx.send(result);
        });
        let output = pipes.pop().unwrap();
        let input = pipes.pop().unwrap();
        let marker = pipes.pop().unwrap();
        Ok(Self {
            marker,
            input,
            output,
            result,
        })
    }

    fn wait_for_transport_opens(&self) -> anyhow::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(/*secs*/ 5);
        loop {
            let mut pid = 0;
            if unsafe { GetNamedPipeClientProcessId(self.output.as_raw_handle() as _, &mut pid) }
                != 0
            {
                assert_eq!(pid, std::process::id());
                return Ok(());
            }
            anyhow::ensure!(
                Instant::now() < deadline,
                "runner did not open transport pipes"
            );
            thread::sleep(Duration::from_millis(/*millis*/ 5));
        }
    }

    fn connect(&self) -> anyhow::Result<()> {
        for pipe in [&self.marker, &self.input, &self.output] {
            let ok = unsafe { ConnectNamedPipe(pipe.as_raw_handle() as _, ptr::null_mut()) };
            if ok == 0 {
                let error = unsafe { GetLastError() };
                anyhow::ensure!(error == ERROR_PIPE_CONNECTED, "connect test pipe: {error}");
            }
        }
        Ok(())
    }

    fn assert_marker_closed(&self) {
        let ok = unsafe {
            PeekNamedPipe(
                self.marker.as_raw_handle() as _,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        let error = unsafe { GetLastError() };
        assert_eq!(ok, 0);
        assert!(
            matches!(error, ERROR_BROKEN_PIPE | ERROR_NO_DATA),
            "marker error: {error}"
        );
    }
}

#[test]
fn concurrent_startup_markers_survive_delayed_parent_and_other_launch_exit() -> anyhow::Result<()> {
    let mut launches = [Launch::start()?, Launch::start()?];
    for launch in &launches {
        launch.wait_for_transport_opens()?;
    }
    // Deliberately let both runners finish their CreateFileW calls and block reading the request
    // before the parent connects. r5 closes both markers in this interval (Windows error 232).
    thread::sleep(Duration::from_millis(/*millis*/ 200));
    for (index, launch) in launches.iter_mut().enumerate() {
        launch.connect()?;
        let request = SpawnRequest {
            command: vec![format!("launch-{index}")],
            cwd: std::env::current_dir()?,
            env: Default::default(),
            permission_profile: PermissionProfile::read_only(),
            workspace_roots: Vec::new(),
            codex_home: std::env::current_dir()?,
            real_codex_home: std::env::current_dir()?,
            cap_sids: Vec::new(),
            network_proxy_restricting_sid: None,
            timeout_ms: None,
            tty: false,
            stdin_open: false,
            private_desktop_name: None,
        };
        write_frame(
            &mut launch.input,
            &FramedMessage {
                version: IPC_PROTOCOL_VERSION,
                message: Message::SpawnRequest {
                    payload: Box::new(request.clone()),
                },
            },
        )?;
        let received = launch
            .result
            .recv_timeout(Duration::from_secs(/*secs*/ 5))??;
        assert_eq!(
            serde_json::to_value(received)?,
            serde_json::to_value(request)?
        );
        launch.assert_marker_closed();
        // Launch 1's pipe guards have now been dropped while launch 2 still awaits its parent.
    }
    Ok(())
}

#[test]
fn rejected_spawn_request_releases_startup_marker() -> anyhow::Result<()> {
    let mut launch = Launch::start()?;
    launch.wait_for_transport_opens()?;
    launch.connect()?;
    write_frame(
        &mut launch.input,
        &FramedMessage {
            version: IPC_PROTOCOL_VERSION,
            message: Message::Terminate {
                payload: Default::default(),
            },
        },
    )?;
    let error = launch
        .result
        .recv_timeout(Duration::from_secs(/*secs*/ 5))?
        .unwrap_err();
    assert!(
        error.to_string().contains("expected spawn_request"),
        "{error:#}"
    );
    launch.assert_marker_closed();
    Ok(())
}
