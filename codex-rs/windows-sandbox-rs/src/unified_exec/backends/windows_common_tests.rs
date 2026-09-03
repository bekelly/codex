//! The result-metric hook must preserve terminal exit codes and pipe-failure behavior.

use super::*;
use crate::ipc_framed::ExitPayload;
use crate::ipc_framed::write_frame;
use pretty_assertions::assert_eq;
use std::io::Seek;

#[test]
fn runner_result_reporting_preserves_exit_and_closed_pipe_results() -> Result<()> {
    for exit_code in [Some(0), Some(23), None] {
        let mut frames = tempfile::tempfile()?;
        if let Some(exit_code) = exit_code {
            write_frame(
                &mut frames,
                &FramedMessage {
                    version: IPC_PROTOCOL_VERSION,
                    message: Message::Exit {
                        payload: ExitPayload {
                            exit_code,
                            timed_out: false,
                        },
                    },
                },
            )?;
        }
        frames.rewind()?;
        let (stdout_tx, _stdout_rx) = broadcast::channel(1);
        let (exit_tx, exit_rx) = oneshot::channel();
        let (teardown_tx, teardown_rx) = std::sync::mpsc::channel();
        start_runner_stdout_reader(
            frames,
            stdout_tx,
            /*stderr_tx*/ None,
            exit_tx,
            move |reason| {
                teardown_tx.send(reason)?;
                Ok(())
            },
        );
        assert_eq!(exit_rx.blocking_recv()?, exit_code.unwrap_or(-1));
        assert_eq!(
            teardown_rx.try_recv()?,
            if exit_code.is_some() {
                RunnerTeardownReason::ExitReceived
            } else {
                RunnerTeardownReason::TransportClosed
            }
        );
    }
    Ok(())
}

#[test]
fn runner_cleanup_failure_overrides_exit_and_reports_diagnostic() -> Result<()> {
    let mut frames = tempfile::tempfile()?;
    write_frame(
        &mut frames,
        &FramedMessage {
            version: IPC_PROTOCOL_VERSION,
            message: Message::Exit {
                payload: ExitPayload {
                    exit_code: 0,
                    timed_out: false,
                },
            },
        },
    )?;
    frames.rewind()?;
    let (stdout_tx, mut stdout_rx) = broadcast::channel(1);
    let (exit_tx, exit_rx) = oneshot::channel();
    start_runner_stdout_reader(
        frames,
        stdout_tx,
        /*stderr_tx*/ None,
        exit_tx,
        |reason| {
            assert_eq!(reason, RunnerTeardownReason::ExitReceived);
            anyhow::bail!("test cleanup failure")
        },
    );
    assert_eq!(exit_rx.blocking_recv()?, -1);
    assert_eq!(
        stdout_rx.try_recv()?,
        b"runner error: runner authority cleanup failed: test cleanup failure\n"
    );
    Ok(())
}
