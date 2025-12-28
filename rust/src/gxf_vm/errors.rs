/* SPDX-License_Identifier: MIT */

use core::{error, fmt};

use crate::gxf_vm::dispatch::GxfDomain;
use crate::gxf_vm::frames::SptmFrameKind;

#[derive(Debug, Clone, Copy)]
pub(crate) enum GxfDispatchError {
    UnknownDomain,
    UnknownEndpoint,
    UnknownTable,
}

impl fmt::Display for GxfDispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use GxfDispatchError::*;

        write!(
            f,
            "{}",
            match self {
                UnknownDomain => "Error decoding GxfDispatcher: Unknown domain",
                UnknownEndpoint => "Error decoding GxfDispatcher: Unknown endpoint",
                UnknownTable => "Error decoding GxfDispatcher: Unknown dispatch table",
            }
        )
    }
}

impl error::Error for GxfDispatchError {}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SptmRetypeError {
    address: u64,
    kind: SptmRetypeErrorKind,
}

impl SptmRetypeError {
    pub(crate) fn new(address: u64, kind: SptmRetypeErrorKind) -> Self {
        Self { address, kind }
    }
}

impl fmt::Display for SptmRetypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Error retyping frame at 0x{:016x}: {}",
            self.address, self.kind
        )
    }
}

impl error::Error for SptmRetypeError {}

#[derive(Debug, Clone, Copy)]
pub(crate) enum SptmRetypeErrorKind {
    InvalidDomain(GxfDomain, SptmFrameKind),
    InvalidFromKind(SptmFrameKind),
    InvalidRetype(SptmFrameKind, SptmFrameKind),
}

impl fmt::Display for SptmRetypeErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use SptmRetypeErrorKind::*;

        match self {
            InvalidDomain(domain, frame) => write!(
                f,
                "Domain '{:?}' is invalid for current frame type '{:?}'.",
                domain, frame
            ),

            InvalidFromKind(frame) => write!(
                f,
                "Specified \"from\" type '{:?}' does not match FTE.",
                frame
            ),

            InvalidRetype(old, new) => write!(
                f,
                "Cannot retype frame from type '{:?}' to '{:?}'.",
                old, new
            ),
        }
    }
}
