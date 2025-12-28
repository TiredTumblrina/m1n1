/* SPDX-License_Identifier: MIT */

use core::convert;

use crate::println;

use crate::gxf_vm::errors::GxfDispatchError;

// An enum representing valid values of `sptm_domain_t`.
// Values taken from Appendix A. 2:
//   (Steffin, Moritz: Modern iOS Security Features)
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub(crate) enum GxfDomain {
    Sptm = 0,
    Xnu = 1,
    Txm = 2,
    Sk = 3,
    Hib = 4,
}

impl convert::TryFrom<u8> for GxfDomain {
    type Error = GxfDispatchError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(GxfDomain::Sptm),
            1 => Ok(GxfDomain::Xnu),
            2 => Ok(GxfDomain::Txm),
            3 => Ok(GxfDomain::Sk),
            4 => Ok(GxfDomain::Hib),
            _ => Err(GxfDispatchError::UnknownDomain),
        }
    }
}

// An enum representing valid values of `sptm_dispatch_table_id_t`.
// Values taken from Appendix A. 3:
//   (Steffin, Moritz: Modern iOS Security Features)
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub(crate) enum GxfDispatchTable {
    XnuBootstrap = 0,
    TxmBootstrap = 1,
    SkBootstrap = 2,
    T8110DartXnu = 3,
    T8110DartSk = 4,
    Sart = 5,
    Nvme = 6,
    Uat = 7,
    Shart = 8,
    Reserved = 9,
    Hib = 10,
    Invalid = 11,
}

impl convert::TryFrom<u8> for GxfDispatchTable {
    type Error = GxfDispatchError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use GxfDispatchTable::*;

        match value {
            0 => Ok(XnuBootstrap),
            1 => Ok(TxmBootstrap),
            2 => Ok(SkBootstrap),
            3 => Ok(T8110DartXnu),
            4 => Ok(T8110DartSk),
            5 => Ok(Sart),
            6 => Ok(Nvme),
            7 => Ok(Uat),
            8 => Ok(Shart),
            9 => Ok(Reserved),
            10 => Ok(Hib),
            11 => Ok(Invalid),
            _ => Err(GxfDispatchError::UnknownTable),
        }
    }
}

// An enum representing valid values of `sptm_dispatch_endpoint_id_t`
// Values taken from Appendix A. 4:
//   (Steffin, Moritz: Modern iOS Security Features).
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub(crate) enum GxfEndpoint {
    LockDown = 0,
    Retype = 1,
    MapPage = 2,
    MapTable = 3,
    UnmapTable = 4,
    UpdateRegion = 5,
    UpdateDisjoint = 6,
    UnmapRegion = 7,
    UnmapDisjoint = 8,
    ConfigureSharedRegion = 9,
    NestRegion = 10,
    UnnestRegion = 11,
    ConfigureRoot = 12,
    SwitchRoot = 13,
    RegisterCpu = 14,
    FixUpsComplete = 15,
    SignUserPointer = 16,
    AuthUserPointer = 17,
    RegisterExcReturn = 18,
    CpuId = 19,
    SlideRegion = 20,
    UpdateDisjointMultipage = 21,
    RegRead = 22,
    RegWrite = 23,
    GuestVaToIpa = 24,
    GuestStage1TlbOp = 25,
    GuestStage2TlbOp = 26,
    GuestDispatch = 27,
    GuestExit = 28,
    MapSkDomain = 29,
    HibBegin = 30,
    HibVerifyHashNonWired = 31,
    HibFinalizeNonWired = 32,
    IoFilterProtectedWrite = 33,
}

impl convert::TryFrom<u32> for GxfEndpoint {
    type Error = GxfDispatchError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        use GxfEndpoint::*;

        match value {
            0 => Ok(LockDown),
            1 => Ok(Retype),
            2 => Ok(MapPage),
            3 => Ok(MapTable),
            4 => Ok(UnmapTable),
            5 => Ok(UpdateRegion),
            6 => Ok(UpdateDisjoint),
            7 => Ok(UnmapRegion),
            8 => Ok(UnmapDisjoint),
            9 => Ok(ConfigureSharedRegion),
            10 => Ok(NestRegion),
            11 => Ok(UnnestRegion),
            12 => Ok(ConfigureRoot),
            13 => Ok(SwitchRoot),
            14 => Ok(RegisterCpu),
            15 => Ok(FixUpsComplete),
            16 => Ok(SignUserPointer),
            17 => Ok(AuthUserPointer),
            18 => Ok(RegisterExcReturn),
            19 => Ok(CpuId),
            20 => Ok(SlideRegion),
            21 => Ok(UpdateDisjointMultipage),
            22 => Ok(RegRead),
            23 => Ok(RegWrite),
            24 => Ok(GuestVaToIpa),
            25 => Ok(GuestStage1TlbOp),
            26 => Ok(GuestStage2TlbOp),
            27 => Ok(GuestDispatch),
            28 => Ok(GuestExit),
            29 => Ok(MapSkDomain),
            30 => Ok(HibBegin),
            31 => Ok(HibVerifyHashNonWired),
            32 => Ok(HibFinalizeNonWired),
            33 => Ok(IoFilterProtectedWrite),
            _ => Err(GxfDispatchError::UnknownEndpoint),
        }
    }
}

// An SPTM Dispatch target `sptm_dispatch_target_t`.
// It doesn't follow the exact same representation
// as the original and is instead translated through
// the `try_from` call.
#[derive(Debug, Clone, Copy)]
pub(crate) struct GxfDispatcher {
    domain: GxfDomain,
    table: GxfDispatchTable,
    endpoint: GxfEndpoint,
}

impl GxfDispatcher {
    pub(crate) fn call(&self) {
        println!("Hello from GXF VM!\n");
        println!("Requested: {:?}.", self);

        todo!()
    }
}

impl convert::TryFrom<u64> for GxfDispatcher {
    type Error = GxfDispatchError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        let domain = GxfDomain::try_from(((value >> 48) & 0xff) as u8)?;
        let table = GxfDispatchTable::try_from(((value >> 32) & 0xff) as u8)?;
        let endpoint = GxfEndpoint::try_from((value & 0xffffffff) as u32)?;

        Ok(Self {
            domain,
            table,
            endpoint,
        })
    }
}
