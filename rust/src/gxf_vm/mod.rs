/* SPDX-License_Identifier: MIT */

#![cfg(feature = "gxf-vm")]

mod data;
mod dispatch;
mod errors;
mod frames;

use crate::gxf_vm::data::GxfVmData;
use crate::gxf_vm::dispatch::GxfDispatcher;
use crate::println;

/// A VM-handled call to genter with the x16 value translated to
/// a dispatcher for simulated GXF.
#[no_mangle]
pub unsafe extern "C" fn gxf_vm_genter(target: u64) {
    let dispatcher = match GxfDispatcher::try_from(target) {
        Ok(t) => t,
        Err(e) => {
            println!("{}", e);
            panic!();
        }
    };

    dispatcher.call();
}

/// Initialize the GXF VM
#[no_mangle]
pub unsafe extern "C" fn gxf_vm_init() {
    gxf_vm_patch_xnu_exceptions();
    GxfVmData::initialize();
}

// Apply a binary patch to have XNU HVC to m1n1 when a UNDEFINED
// `genter` is executed.
fn gxf_vm_patch_xnu_exceptions() {
    todo!()
}
