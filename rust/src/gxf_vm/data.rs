/* SPDX-License_Identifier: MIT */

use core::sync::atomic::{AtomicBool, Ordering};

static mut GXF_DATA: Option<GxfVmData> = None;

const MAX_ATTEMPTS: usize = 1000;

#[derive(Debug)]
pub(crate) struct GxfVmData {
    owned: AtomicBool,
}

impl GxfVmData {
    fn acquire(&mut self) -> bool {
        for _ in 0..MAX_ATTEMPTS {
            if self
                .owned
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }

        false
    }

    #[allow(static_mut_refs)]
    pub(crate) fn lock() -> Option<GxfVmDataRef> {
        unsafe {
            match &mut GXF_DATA {
                Some(d) => {
                    if d.acquire() {
                        Some(GxfVmDataRef { data: d })
                    } else {
                        None
                    }
                }

                None => None,
            }
        }
    }

    fn new() -> Self {
        let owned = AtomicBool::new(false);

        Self { owned }
    }

    pub(crate) fn initialize() {
        unsafe {
            match GXF_DATA {
                Some(_) => return,
                None => {}
            }

            GXF_DATA = Some(GxfVmData::new());
        }
    }
}

pub(crate) struct GxfVmDataRef {
    data: &'static mut GxfVmData,
}

#[allow(static_mut_refs)]
impl Drop for GxfVmDataRef {
    fn drop(&mut self) {
        let _ = self;

        unsafe {
            match &mut GXF_DATA {
                Some(d) => {
                    d.owned
                        .compare_exchange(true, false, Ordering::Relaxed, Ordering::Relaxed)
                        .expect("Only the current process should have access to the `&'static mut GxfVmData`...");
                }

                None => unreachable!(),
            }
        }
    }
}

impl AsMut<GxfVmData> for GxfVmDataRef {
    fn as_mut(&mut self) -> &mut GxfVmData {
        self.data
    }
}
