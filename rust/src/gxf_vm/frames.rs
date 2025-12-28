/* SPDX-License_Identifier: MIT */

use crate::gxf_vm::dispatch::GxfDomain;
use crate::gxf_vm::errors::{SptmRetypeError, SptmRetypeErrorKind};

pub(crate) struct SptmFrame {
    address: u64,
    kind: SptmFrameKind,
}

impl SptmFrame {
    pub(crate) fn retype(
        &mut self,
        from: SptmFrameKind,
        to: SptmFrameKind,
        domain: GxfDomain,
    ) -> Option<SptmRetypeError> {
        if self.kind != from {
            return Some(SptmRetypeError::new(
                self.address,
                SptmRetypeErrorKind::InvalidFromKind(from),
            ));
        }

        if let Some(k) = self.kind.retypable(domain, to) {
            return Some(SptmRetypeError::new(self.address, k));
        }

        todo!("More retype checks");

        self.kind = to;

        None
    }
}

// An enum representing valid values of `sptm_frame_type_t`.
// Values taken from Appendix A. 11:
//   (Steffin, Moritz: Modern iOS Security Features).
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum SptmFrameKind {
    Untyped = 0,
    SptmUnused = 1,
    SptmDefault = 2,
    SptmReadOnly = 3,
    SptmCode = 4,
    SptmTxmCode = 5,
    SptmXnuCode = 6,
    SptmXnuCodeDebug = 7,
    SptmKernelRootTable = 8,
    SptmPageTable = 9,
    SptmIommuBootstrap = 10,
    XnuDefault = 11,
    XnuReadOnly = 12,
    XnuReadOnlyDebug = 13,
    XnuUserExec = 14,
    XnuUserDebug = 15,
    XnuUserJit = 16,
    XnuUserRootTable = 17,
    XnuSharedRootTable = 18,
    XnuPageTable = 19,
    XnuPageTableShared = 20,
    XnuPageTableROZone = 21,
    XnuPageTableCommPage = 22,
    XnuIommu = 23,
    XnuROZone = 24,
    XnuIO = 25,
    XnuProtectedIO = 26,
    XnuCommPageReadWrite = 27,
    XnuCommPageReadOnly = 28,
    XnuCommPageReadExec = 29,
    XnuTagStorage = 30,
    XnuStage2RootTable = 31,
    XnuStage2PageTable = 32,
    XnuKernelRestricted = 33,
    XnuReserved1 = 34,
    XnuReserved2 = 35,
    XnuRestrictedIO = 36,
    XnuRestrictedIOTelemetry = 37,
    TxmDefault = 38,
    TxmReadOnly = 39,
    TxmReadWrite = 40,
    TxmCpuStack = 41,
    TxmThreadStack = 42,
    TxmAddressSpaceTable = 43,
    TxmMallocPage = 44,
    TxmFreeList = 45,
    TxmSlabTrustCache = 46,
    TxmSlabProfile = 47,
    TxmSlabCodeSignature = 48,
    TxmSlabCodeRegion = 49,
    TxmSlabAddressSpace = 50,
    TxmBucket1024 = 51,
    TxmBucket2048 = 52,
    TxmBucket4096 = 53,
    TxmBucket8192 = 54,
    TxmBulkData = 55,
    TxmBulkDataReadOnly = 56,
    TxmLog = 57,
    TxmSepSecureChannel = 58,
    SkDefault = 59,
    SkSharedReadOnly = 60,
    SkSharedReadWrite = 61,
    SkIo = 62,
}

// Function gating which kinds of frame retypes should be allowed.
// Based on Appendices A. 12 & 23:
//   (Steffin, Moritz: Modern iOS Security Features)
impl SptmFrameKind {
    pub(crate) fn retypable(
        &self,
        by: GxfDomain,
        to: SptmFrameKind,
    ) -> Option<SptmRetypeErrorKind> {
        use SptmFrameKind::*;

        let _ = to;

        match (self, by) {
            (Untyped, _) => {}

            (SptmUnused, GxfDomain::Sptm) => {}
            (SptmDefault, GxfDomain::Sptm) => {}
            (SptmReadOnly, GxfDomain::Sptm) => {}
            (SptmCode, GxfDomain::Sptm) => {}
            (SptmTxmCode, GxfDomain::Sptm) => {}
            (SptmXnuCode, GxfDomain::Sptm) => {}
            (SptmXnuCodeDebug, GxfDomain::Sptm) => {}
            (SptmKernelRootTable, GxfDomain::Sptm) => {}
            (SptmPageTable, GxfDomain::Sptm) => {}
            (SptmIommuBootstrap, GxfDomain::Sptm) => {}
            (XnuTagStorage, GxfDomain::Sptm) => {}

            (XnuDefault, GxfDomain::Xnu) => {}
            (XnuReadOnly, GxfDomain::Xnu) => {}
            (XnuReadOnlyDebug, GxfDomain::Xnu) => {}
            (XnuUserExec, GxfDomain::Xnu) => {}
            (XnuUserDebug, GxfDomain::Xnu) => {}
            (XnuUserJit, GxfDomain::Xnu) => {}
            (XnuUserRootTable, GxfDomain::Xnu) => {}
            (XnuSharedRootTable, GxfDomain::Xnu) => {}
            (XnuPageTable, GxfDomain::Xnu) => {}
            (XnuPageTableShared, GxfDomain::Xnu) => {}
            (XnuPageTableROZone, GxfDomain::Xnu) => {}
            (XnuPageTableCommPage, GxfDomain::Xnu) => {}
            (XnuIommu, GxfDomain::Xnu) => {}
            (XnuROZone, GxfDomain::Xnu) => {}
            (XnuIO, GxfDomain::Xnu) => {}
            (XnuProtectedIO, GxfDomain::Xnu) => {}
            (XnuCommPageReadWrite, GxfDomain::Xnu) => {}
            (XnuCommPageReadOnly, GxfDomain::Xnu) => {}
            (XnuCommPageReadExec, GxfDomain::Xnu) => {}
            (XnuStage2RootTable, GxfDomain::Xnu) => {}
            (XnuStage2PageTable, GxfDomain::Xnu) => {}
            (XnuKernelRestricted, GxfDomain::Xnu) => {}
            (XnuReserved1, GxfDomain::Xnu) => {}
            (XnuReserved2, GxfDomain::Xnu) => {}
            (XnuRestrictedIO, GxfDomain::Xnu) => {}
            (XnuRestrictedIOTelemetry, GxfDomain::Xnu) => {}

            (TxmDefault, GxfDomain::Txm) => {}
            (TxmReadOnly, GxfDomain::Txm) => {}
            (TxmReadWrite, GxfDomain::Txm) => {}
            (TxmCpuStack, GxfDomain::Txm) => {}
            (TxmThreadStack, GxfDomain::Txm) => {}
            (TxmAddressSpaceTable, GxfDomain::Txm) => {}
            (TxmMallocPage, GxfDomain::Txm) => {}
            (TxmFreeList, GxfDomain::Txm) => {}
            (TxmSlabTrustCache, GxfDomain::Txm) => {}
            (TxmSlabProfile, GxfDomain::Txm) => {}
            (TxmSlabCodeSignature, GxfDomain::Txm) => {}
            (TxmSlabCodeRegion, GxfDomain::Txm) => {}
            (TxmSlabAddressSpace, GxfDomain::Txm) => {}
            (TxmBucket1024, GxfDomain::Txm) => {}
            (TxmBucket2048, GxfDomain::Txm) => {}
            (TxmBucket4096, GxfDomain::Txm) => {}
            (TxmBucket8192, GxfDomain::Txm) => {}
            (TxmBulkData, GxfDomain::Txm) => {}
            (TxmBulkDataReadOnly, GxfDomain::Txm) => {}
            (TxmLog, GxfDomain::Txm) => {}
            (TxmSepSecureChannel, GxfDomain::Txm) => {}

            (SkDefault, GxfDomain::Sk) => {}
            (SkSharedReadOnly, GxfDomain::Sk) => {}
            (SkSharedReadWrite, GxfDomain::Sk) => {}
            (SkIo, GxfDomain::Sk) => {}

            _ => return Some(SptmRetypeErrorKind::InvalidDomain(by, *self)),
        };

        match (self, to) {
            (Untyped, _) => {}

            (
                XnuDefault,
                SptmUnused | XnuDefault | XnuUserExec | XnuUserDebug | XnuUserJit
                | XnuUserRootTable | XnuPageTable | XnuPageTableShared | XnuPageTableROZone
                | XnuPageTableCommPage | XnuIommu | XnuROZone | XnuCommPageReadExec
                | XnuCommPageReadOnly | XnuCommPageReadWrite | XnuStage2RootTable
                | XnuStage2PageTable | XnuKernelRestricted | XnuReserved2 | TxmDefault | SkDefault,
            ) => {}

            (XnuUserExec, XnuDefault) => {}
            (XnuUserDebug, XnuDefault) => {}
            (XnuUserJit, XnuDefault) => {}
            (XnuUserRootTable, XnuDefault | XnuSharedRootTable) => {}
            (XnuSharedRootTable, XnuDefault) => {}
            (XnuPageTable, XnuDefault) => {}
            (XnuPageTableShared, XnuDefault) => {}
            (XnuIommu, XnuDefault) => {}
            (XnuROZone, XnuDefault) => {}
            (XnuStage2RootTable, XnuDefault) => {}
            (XnuStage2PageTable, XnuDefault) => {}
            (XnuKernelRestricted, XnuDefault | XnuKernelRestricted) => {}
            (XnuReserved2, XnuDefault) => {}
            (TxmDefault, TxmFreeList | TxmBulkData | TxmBulkDataReadOnly) => {}
            (
                TxmFreeList,
                XnuDefault | TxmSlabTrustCache | TxmSlabProfile | TxmSlabCodeSignature
                | TxmSlabCodeRegion | TxmSlabAddressSpace | TxmBucket1024 | TxmBucket2048
                | TxmBucket4096 | TxmBucket8192,
            ) => {}
            (TxmBulkData, XnuDefault | TxmBulkDataReadOnly) => {}
            (TxmBulkDataReadOnly, XnuDefault) => {}
            (SkDefault, XnuDefault | SkSharedReadOnly | SkSharedReadWrite) => {}
            (SkSharedReadOnly, SkDefault | SkSharedReadWrite) => {}
            (SkSharedReadWrite, SkDefault | SkSharedReadOnly) => {}

            _ => return Some(SptmRetypeErrorKind::InvalidRetype(to, *self)),
        }

        None
    }
}
