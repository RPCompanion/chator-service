//! Guarded reads of game memory: committed-and-readable checks (VirtualQuery) and the RTTI class
//! names of live objects.

use std::mem;

/// Readability of addresses, remembering the last region VirtualQuery described so that a scan
/// over many pointers into the same heap region queries it once.
#[derive(Default)]
pub struct Regions {
    start: usize,
    end: usize,
    readable: bool,
}

impl Regions {
    /// Whether the 8 bytes at `address` are committed, readable memory.
    pub fn readable(&mut self, address: usize) -> bool {
        use windows::Win32::System::Memory::*;
        if !(self.start..self.end).contains(&address) {
            let mut info = MEMORY_BASIC_INFORMATION::default();
            let size = unsafe {
                VirtualQuery(Some(address as *const _), &mut info, mem::size_of::<MEMORY_BASIC_INFORMATION>())
            };
            if size == 0 {
                return false;
            }
            let readable = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
            *self = Regions {
                start: info.BaseAddress as usize,
                end: info.BaseAddress as usize + info.RegionSize,
                readable: info.State == MEM_COMMIT
                    && (info.Protect & readable).0 != 0
                    && (info.Protect & (PAGE_GUARD | PAGE_NOACCESS)).0 == 0,
            };
        }
        self.readable && address + 8 <= self.end
    }
}

pub fn is_readable(address: usize) -> bool {
    Regions::default().readable(address)
}

/// The pointer-sized value at `address`, if that memory is readable.
pub fn read_usize(address: usize) -> Option<usize> {
    is_readable(address).then(|| unsafe { *(address as *const usize) })
}

/// Whether the object at `object` is a `class` (exact MSVC RTTI type, not a base class): its
/// vtable's CompleteObjectLocator names the type descriptor `.?AV<class>@@` in the module at
/// `base` (swtor.exe).
pub fn is_class(base: usize, object: usize, class: &str) -> bool {
    let wanted = format!(".?AV{class}@@\0");
    let Some(vtable) = read_usize(object) else { return false };
    let Some(locator) = vtable.checked_sub(8).and_then(read_usize) else { return false };
    if !is_readable(locator + 12) {
        return false;
    }
    let descriptor = unsafe { *((locator + 12) as *const u32) } as usize;
    let name = base + descriptor + 16;
    // The name may cross into the next region; check both ends.
    if !is_readable(name) || !is_readable(name + wanted.len() - 8) {
        return false;
    }
    let bytes = unsafe { std::slice::from_raw_parts(name as *const u8, wanted.len()) };
    bytes == wanted.as_bytes()
}
