//! Small timeout wrappers around Tokio I/O operations.
//!
//! Centralizing these calls keeps protocol handlers from waiting forever on a
//! peer that stops sending bytes mid-handshake.

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Duration, timeout};

const IO_TIMEOUT: Duration = Duration::from_secs(180);

/// Build a consistent timeout error message.
fn timeout_message(action: &str) -> String {
    format!("{action} timed out after {}s", IO_TIMEOUT.as_secs())
}

/// Read bytes from a stream with the shared I/O timeout.
pub async fn read_with_timeout<S>(stream: &mut S, buf: &mut [u8], action: &str) -> Result<usize>
where
    S: AsyncRead + Unpin,
{
    let n = timeout(IO_TIMEOUT, stream.read(buf))
        .await
        .with_context(|| timeout_message(action))??;
    Ok(n)
}

/// Read an exact buffer from a stream with the shared I/O timeout.
pub async fn read_exact_with_timeout<S>(stream: &mut S, buf: &mut [u8], action: &str) -> Result<()>
where
    S: AsyncRead + Unpin,
{
    let _ = timeout(IO_TIMEOUT, stream.read_exact(buf))
        .await
        .with_context(|| timeout_message(action))??;
    Ok(())
}

/// Write all bytes to a stream with the shared I/O timeout.
pub async fn write_all_with_timeout<S>(stream: &mut S, buf: &[u8], action: &str) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    timeout(IO_TIMEOUT, stream.write_all(buf))
        .await
        .with_context(|| timeout_message(action))??;
    Ok(())
}

/// Flush a stream with the shared I/O timeout.
pub async fn flush_with_timeout<S>(stream: &mut S, action: &str) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    timeout(IO_TIMEOUT, stream.flush())
        .await
        .with_context(|| timeout_message(action))??;
    Ok(())
}
