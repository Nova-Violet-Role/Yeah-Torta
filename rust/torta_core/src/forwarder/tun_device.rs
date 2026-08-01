/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! N1 — the ASYNC TUN DEVICE (the `AsyncRead + AsyncWrite` adapter over the raw tun fd).
//!
//! ipstack drives off a `device: AsyncRead + AsyncWrite + Unpin + Send` (`IpStack::new`, verified 2026-07-05).
//! Our tun fd is a raw POSIX fd (dup'd from Kotlin's `detachFd`, `tunnel/mod.rs:352`). This adapter is the
//! bridge: tokio's [`AsyncFd`] registers the fd with the reactor for readiness, and we implement
//! [`AsyncRead`]/[`AsyncWrite`] by `read`/`write` on the fd inside a readiness guard. The Rust twin of
//! firestack's `fdbased.go` LinkEndpoint (the tun-fd ↔ netstack I/O), but async/tokio instead of a Go
//! goroutine + `readv`.
//!
//! The fd MUST be set non-blocking (`O_NONBLOCK`) — `AsyncFd` requires it (a blocking read would stall the
//! whole tokio worker). [`AsyncTunDevice::from_owned`] sets it via `fcntl` before registering. The device
//! OWNS the fd (an `OwnedFd`), closing it on drop — the same ownership contract as the sync `run_loop`.
//!
//! One packet per read/write: a tun fd is packet-oriented (each `read` returns exactly one IP packet, each
//! `write` sends one), which is what ipstack's `AsyncRead`/`AsyncWrite` expects for a tun (vs a byte stream).

use std::io;
use std::os::unix::io::{AsRawFd, OwnedFd};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// An async, tokio-reactor-registered view of the tun fd — the `device` handed to `ipstack::IpStack::new`.
/// Owns the fd (closed on drop). Non-blocking is set at construction.
pub(crate) struct AsyncTunDevice {
    inner: AsyncFd<OwnedFd>,
}

impl AsyncTunDevice {
    /// Wrap an owned tun fd for async I/O: set `O_NONBLOCK` (AsyncFd requires it), then register with the
    /// tokio reactor. Fails if the fd is invalid or fcntl/registration fails (the caller falls back to the
    /// sync DNS-only loop — never a hard crash). MUST be called from within a tokio runtime context.
    pub(crate) fn from_owned(fd: OwnedFd) -> io::Result<Self> {
        // Set O_NONBLOCK — the AsyncFd contract (a blocking read would stall the tokio worker).
        // SAFETY: `fcntl` with F_GETFL/F_SETFL on a valid owned fd is the documented POSIX contract.
        let raw = fd.as_raw_fd();
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let rc = unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(AsyncTunDevice {
            inner: AsyncFd::new(fd)?,
        })
    }
}

impl AsyncRead for AsyncTunDevice {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            // Wait for read readiness on the fd.
            let mut guard = match self.inner.poll_read_ready(cx) {
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            // One packet per read. `read` into the uninit tail of the ReadBuf.
            let raw = guard.get_inner().as_raw_fd();
            let unfilled = buf.initialize_unfilled();
            // SAFETY: `read` into a valid mutable buffer of `len` bytes; the fd is owned + non-blocking.
            let n = unsafe {
                libc::read(
                    raw,
                    unfilled.as_mut_ptr() as *mut libc::c_void,
                    unfilled.len(),
                )
            };
            if n >= 0 {
                buf.advance(n as usize);
                return Poll::Ready(Ok(()));
            }
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                // Readiness was spurious — clear it and re-poll.
                guard.clear_ready();
                continue;
            }
            return Poll::Ready(Err(err));
        }
    }
}

impl AsyncWrite for AsyncTunDevice {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = match self.inner.poll_write_ready(cx) {
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            let raw = guard.get_inner().as_raw_fd();
            // SAFETY: `write` from a valid buffer of `buf.len()` bytes; the fd is owned + non-blocking.
            let n = unsafe { libc::write(raw, buf.as_ptr() as *const libc::c_void, buf.len()) };
            if n >= 0 {
                return Poll::Ready(Ok(n as usize));
            }
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                guard.clear_ready();
                continue;
            }
            return Poll::Ready(Err(err));
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // A tun fd is packet-oriented — each write is delivered immediately; nothing to flush.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Shutdown = drop the device (closes the fd). Nothing half-close-able about a tun fd.
        Poll::Ready(Ok(()))
    }
}
