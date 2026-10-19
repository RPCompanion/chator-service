//! Runtime signature scanning of the loaded swtor.exe image.
//!
//! Finds hook targets by landmark instead of hardcoded RVAs so that the DLL
//! survives game updates. Everything here reads the mapped PE image of the
//! process we are injected into; nothing is written.
//!
//! Technique for `chat_recv`:
//!   1. Find the UTF-16 string "ReceiveChatMessage" in `.rdata`.
//!   2. Find the `LEA reg, [rip+disp32]` in `.text` whose target is that string.
//!      There is exactly one in every build seen so far.
//!   3. Look the reference up in the PE exception directory (`.pdata`) to get
//!      the start of the enclosing function, following chained unwind info.
//!
//! `cmd_dispatch` is found by a constant inside it, and the vtables of its global pointer chain
//! by their MSVC RTTI class names (see `find_chain_vtables`).

use std::slice;

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
const UNW_FLAG_CHAININFO: u8 = 0x4;

#[derive(Clone, Debug)]
pub struct Section {
    pub name: String,
    pub rva: u32,
    pub size: u32,
}

pub struct PeImage {
    base: usize,
    /// ImageBase from the optional header: what absolute addresses in an unrelocated image
    /// (laid out from disk, in tests) are relative to.
    preferred_base: u64,
    image_size: u32,
    sections: Vec<Section>,
    pdata_rva: u32,
    pdata_size: u32,
}

#[derive(Clone, Copy, Debug)]
struct RuntimeFunction {
    begin: u32,
    end: u32,
    unwind: u32,
}

impl PeImage {
    /// Parses the PE headers of the module mapped at `base`.
    pub unsafe fn parse(base: usize) -> Result<PeImage, String> {
        unsafe {
            let rd16 = |off: usize| -> u16 { *((base + off) as *const u16) };
            let rd32 = |off: usize| -> u32 { *((base + off) as *const u32) };

            if rd16(0) != IMAGE_DOS_SIGNATURE {
                return Err("bad DOS signature".into());
            }
            let pe = rd32(0x3c) as usize;
            if pe > 0x1000 || rd32(pe) != IMAGE_NT_SIGNATURE {
                return Err("bad PE signature".into());
            }
            let num_sections = rd16(pe + 6) as usize;
            let opt_size = rd16(pe + 20) as usize;
            let opt = pe + 24;
            if rd16(opt) != 0x20b {
                return Err("not a PE32+ image".into());
            }
            let preferred_base = *((base + opt + 24) as *const u64);
            let image_size = rd32(opt + 56);
            let num_dirs = rd32(opt + 108) as usize;
            if num_dirs <= IMAGE_DIRECTORY_ENTRY_EXCEPTION {
                return Err("no exception directory".into());
            }
            let dir = opt + 112 + 8 * IMAGE_DIRECTORY_ENTRY_EXCEPTION;
            let pdata_rva = rd32(dir);
            let pdata_size = rd32(dir + 4);

            let mut sections = Vec::with_capacity(num_sections);
            let sec_base = opt + opt_size;
            for i in 0..num_sections {
                let s = sec_base + 40 * i;
                let name_bytes = slice::from_raw_parts((base + s) as *const u8, 8);
                let name = String::from_utf8_lossy(name_bytes)
                    .trim_end_matches('\0')
                    .to_string();
                let vsize = rd32(s + 8);
                let rva = rd32(s + 12);
                let rsize = rd32(s + 16);
                sections.push(Section {
                    name,
                    rva,
                    size: vsize.max(rsize),
                });
            }

            Ok(PeImage {
                base,
                preferred_base,
                image_size,
                sections,
                pdata_rva,
                pdata_size,
            })
        }
    }

    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }

    pub fn image_size(&self) -> u32 {
        self.image_size
    }

    /// Returns the mapped bytes of a section (clamped to the image size).
    pub unsafe fn section_bytes(&self, sec: &Section) -> &[u8] {
        let end = (sec.rva as u64 + sec.size as u64).min(self.image_size as u64) as u32;
        let len = end.saturating_sub(sec.rva) as usize;
        unsafe { slice::from_raw_parts((self.base + sec.rva as usize) as *const u8, len) }
    }

    /// Finds a null-terminated UTF-16LE string (exact match, bounded by nulls)
    /// inside the given section. Returns RVAs of each occurrence.
    pub unsafe fn find_utf16_string(&self, sec: &Section, text: &str) -> Vec<u32> {
        let needle: Vec<u8> = text
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let hay = unsafe { self.section_bytes(sec) };
        let mut hits = Vec::new();
        if needle.is_empty() || hay.len() < needle.len() + 2 {
            return hits;
        }
        let mut i = 0usize;
        // UTF-16 strings are 2-byte aligned.
        while i + needle.len() + 2 <= hay.len() {
            if hay[i..i + needle.len()] == needle[..] {
                let after_null = hay[i + needle.len()] == 0 && hay[i + needle.len() + 1] == 0;
                let before_null = i < 2 || (hay[i - 2] == 0 && hay[i - 1] == 0);
                if after_null && before_null {
                    hits.push(sec.rva + i as u32);
                }
            }
            i += 2;
        }
        hits
    }

    /// Scans `.text` for `LEA r64, [rip+disp32]` instructions whose target is
    /// `target_rva`. Returns the RVAs of the matching instructions.
    pub unsafe fn find_lea_refs(&self, target_rva: u32) -> Vec<u32> {
        let mut hits = Vec::new();
        let Some(text) = self.section(".text") else {
            return hits;
        };
        let code = unsafe { self.section_bytes(text) };
        if code.len() < 7 {
            return hits;
        }
        for i in 0..code.len() - 7 {
            let rex = code[i];
            if rex != 0x48 && rex != 0x4c && rex != 0x49 && rex != 0x4d {
                continue;
            }
            if code[i + 1] != 0x8d {
                continue;
            }
            // mod=00, rm=101 => RIP-relative; reg field is free.
            if code[i + 2] & 0xc7 != 0x05 {
                continue;
            }
            let disp = i32::from_le_bytes([code[i + 3], code[i + 4], code[i + 5], code[i + 6]]);
            let insn_rva = text.rva as i64 + i as i64;
            let target = insn_rva + 7 + disp as i64;
            if target == target_rva as i64 {
                hits.push(insn_rva as u32);
            }
        }
        hits
    }

    /// Whether `value`, read from the image, is the address of `rva` (relocated, or relative to
    /// the preferred base when the image was laid out from disk).
    fn points_to(&self, value: u64, rva: u32) -> bool {
        value == self.base as u64 + rva as u64 || value == self.preferred_base + rva as u64
    }

    /// Finds a class's primary vtable through MSVC RTTI and returns its RVA: the type
    /// descriptor holding the decorated name (`.?AV<class>@@`, in `.data`), the
    /// CompleteObjectLocator in `.rdata` that refers to it (signature 1, offset 0, its own RVA
    /// last), then the `.rdata` slot pointing at that locator, which sits right before the vtable.
    pub unsafe fn find_vtable_by_rtti(&self, class: &str) -> Result<u32, String> {
        unsafe { self.find_subobject_vtable(class, 0) }
    }

    /// RVAs of the RTTI type descriptors named `.?AV<class>@@`.
    unsafe fn type_descriptors(&self, class: &str) -> Result<Vec<u32>, String> {
        let name = format!(".?AV{class}@@\0");
        let data = self.section(".data").ok_or_else(|| ".data section not found".to_string())?;
        let data_bytes = unsafe { self.section_bytes(data) };
        // A type descriptor is a vtable pointer and a spare pointer, then the name.
        Ok(find_all(data_bytes, name.as_bytes())
            .filter_map(|at| (data.rva as usize + at).checked_sub(16).map(|d| d as u32))
            .collect())
    }

    /// RVAs of the CompleteObjectLocators of `class` whose subobject offset is `offset`.
    unsafe fn object_locators(&self, class: &str, offset: u32) -> Result<Vec<u32>, String> {
        let rdata = self.section(".rdata").ok_or_else(|| ".rdata section not found".to_string())?;
        let rdata_bytes = unsafe { self.section_bytes(rdata) };
        let u32_at = |i: usize| u32::from_le_bytes(rdata_bytes[i..i + 4].try_into().unwrap());
        let descriptors = unsafe { self.type_descriptors(class)? };
        let mut out = Vec::new();
        for col in (0..rdata_bytes.len().saturating_sub(24)).step_by(4) {
            let col_rva = rdata.rva + col as u32;
            if u32_at(col) == 1 && u32_at(col + 4) == offset && descriptors.contains(&u32_at(col + 12)) && u32_at(col + 20) == col_rva {
                out.push(col_rva);
            }
        }
        Ok(out)
    }

    /// Like find_vtable_by_rtti, for the vtable of the base-class subobject at `offset` (see
    /// base_class_offset).
    pub unsafe fn find_subobject_vtable(&self, class: &str, offset: u32) -> Result<u32, String> {
        let rdata = self.section(".rdata").ok_or_else(|| ".rdata section not found".to_string())?;
        let rdata_bytes = unsafe { self.section_bytes(rdata) };

        let mut vtables = Vec::new();
        for col_rva in unsafe { self.object_locators(class, offset)? } {
            for slot in (0..rdata_bytes.len().saturating_sub(8)).step_by(8) {
                let value = u64::from_le_bytes(rdata_bytes[slot..slot + 8].try_into().unwrap());
                if self.points_to(value, col_rva) {
                    vtables.push(rdata.rva + slot as u32 + 8);
                }
            }
        }
        match vtables.as_slice() {
            [one] => Ok(*one),
            [] => Err(format!("no vtable found for {class} at +{offset}")),
            many => Err(format!("{} vtables found for {class} at +{offset}: {:x?}", many.len(), many)),
        }
    }

    /// Where base class `base` sits inside `class` (the `mdisp` of its BaseClassDescriptor in
    /// the RTTI class hierarchy of `class`).
    pub unsafe fn base_class_offset(&self, class: &str, base: &str) -> Result<u32, String> {
        let rd32 = |rva: u32| -> Option<u32> {
            (rva < self.image_size.saturating_sub(4)).then(|| unsafe { *((self.base + rva as usize) as *const u32) })
        };
        let wanted = format!(".?AV{base}@@");
        let col = *unsafe { self.object_locators(class, 0)? }
            .first()
            .ok_or_else(|| format!("no object locator for {class}"))?;
        let hierarchy = rd32(col + 16).ok_or("bad class hierarchy pointer")?;
        let count = rd32(hierarchy + 8).ok_or("bad base class count")?;
        let array = rd32(hierarchy + 12).ok_or("bad base class array")?;
        for i in 0..count.min(64) {
            let Some(descriptor) = rd32(array + 4 * i) else { continue };
            let Some(type_descriptor) = rd32(descriptor) else { continue };
            if type_descriptor >= self.image_size.saturating_sub(16 + wanted.len() as u32) {
                continue;
            }
            let name = unsafe { slice::from_raw_parts((self.base + type_descriptor as usize + 16) as *const u8, wanted.len() + 1) };
            if name[..wanted.len()] == *wanted.as_bytes() && name[wanted.len()] == 0 {
                return rd32(descriptor + 8).ok_or_else(|| "bad base class offset".to_string());
            }
        }
        Err(format!("{base} is not a base class of {class}"))
    }

    /// RVA of the function in slot `index` of the vtable at `vtable` (RVA), if it is in `.text`.
    pub unsafe fn vtable_entry(&self, vtable: u32, index: u32) -> Option<u32> {
        let slot = vtable as usize + 8 * index as usize;
        if slot + 8 > self.image_size as usize {
            return None;
        }
        let value = unsafe { *((self.base + slot) as *const u64) };
        let text = self.section(".text")?;
        [self.base as u64, self.preferred_base]
            .iter()
            .filter_map(|b| value.checked_sub(*b))
            .find(|rva| (text.rva as u64..text.rva as u64 + text.size as u64).contains(rva))
            .map(|rva| rva as u32)
    }

    /// The one function (per `.pdata`) containing every RVA in `refs`, as (begin, end).
    pub unsafe fn unique_function(&self, refs: &[u32]) -> Result<(u32, u32), String> {
        let mut starts: Vec<(u32, u32)> = Vec::new();
        for r in refs {
            match unsafe { self.function_bounds(*r) } {
                Some(b) => {
                    if !starts.contains(&b) {
                        starts.push(b);
                    }
                }
                None => {
                    return Err(format!("reference at 0x{:x} has no .pdata entry", r));
                }
            }
        }
        if starts.len() != 1 {
            return Err(format!(
                "landmark references resolve to {} different functions: {:?}",
                starts.len(),
                starts
                    .iter()
                    .map(|(b, e)| format!("0x{:x}..0x{:x}", b, e))
                    .collect::<Vec<_>>()
            ));
        }
        Ok(starts[0])
    }

    unsafe fn runtime_functions(&self) -> &[[u32; 3]] {
        if self.pdata_rva == 0 || self.pdata_size < 12 {
            return &[];
        }
        unsafe {
            slice::from_raw_parts(
                (self.base + self.pdata_rva as usize) as *const [u32; 3],
                (self.pdata_size / 12) as usize,
            )
        }
    }

    /// Finds the function containing `rva` via the exception directory and
    /// follows chained unwind info to the primary entry. Returns (begin, end).
    pub unsafe fn function_bounds(&self, rva: u32) -> Option<(u32, u32)> {
        let table = unsafe { self.runtime_functions() };
        if table.is_empty() {
            return None;
        }
        // .pdata is sorted by begin address.
        let idx = table.partition_point(|e| e[0] <= rva);
        if idx == 0 {
            return None;
        }
        let mut rf = RuntimeFunction {
            begin: table[idx - 1][0],
            end: table[idx - 1][1],
            unwind: table[idx - 1][2],
        };
        if !(rf.begin <= rva && rva < rf.end) {
            return None;
        }
        for _ in 0..16 {
            if rf.unwind == 0 || rf.unwind >= self.image_size {
                break;
            }
            let uw = (self.base + rf.unwind as usize) as *const u8;
            let flags = unsafe { *uw } >> 3;
            if flags & UNW_FLAG_CHAININFO == 0 {
                break;
            }
            let count = unsafe { *uw.add(2) } as usize;
            let chained = unsafe { uw.add(4 + ((count + 1) & !1) * 2) } as *const u32;
            rf = unsafe {
                RuntimeFunction {
                    begin: *chained,
                    end: *chained.add(1),
                    unwind: *chained.add(2),
                }
            };
        }
        Some((rf.begin, rf.end))
    }
}

/// Result of a successful scan.
#[derive(Debug, Clone)]
pub struct ScanHit {
    pub rva: u32,
    pub detail: String,
}

/// Locates the chat receive handler by its "ReceiveChatMessage" landmark.
pub unsafe fn find_chat_recv(base: usize) -> Result<ScanHit, String> {
    const LANDMARK: &str = "ReceiveChatMessage";
    unsafe {
        let pe = PeImage::parse(base)?;
        let rdata = pe
            .section(".rdata")
            .ok_or_else(|| ".rdata section not found".to_string())?;

        let strings = pe.find_utf16_string(rdata, LANDMARK);
        if strings.is_empty() {
            return Err(format!("landmark string {:?} not found in .rdata", LANDMARK));
        }

        let mut refs: Vec<u32> = Vec::new();
        for s in &strings {
            refs.extend(pe.find_lea_refs(*s));
        }
        if refs.is_empty() {
            return Err(format!(
                "no LEA references to {:?} (string at {:?})",
                LANDMARK,
                strings.iter().map(|s| format!("0x{:x}", s)).collect::<Vec<_>>()
            ));
        }

        let (begin, end) = pe.unique_function(&refs)?;
        Ok(ScanHit {
            rva: begin,
            detail: format!(
                "string 0x{:x}, {} ref(s) (first 0x{:x}), function 0x{:x}..0x{:x}",
                strings[0],
                refs.len(),
                refs[0],
                begin,
                end
            ),
        })
    }
}

/// RPC method IDs. Every server call is a generated proxy method that passes its ID to the shared
/// send routine (`mov r8d, id`), so the ID locates the method (see
/// frida-scripts/chat_send_routes_oct2026.md).
pub mod rpc {
    /// AreaServerRequestIFaceProxy: emote / say / yell (cmd_dispatch).
    pub const CMD_DISPATCH: u32 = 0x41d9_8bec;
    /// ChatGatewayRequestIFaceProxy: message to a channel (guild, general, ...).
    pub const CHANNEL_MESSAGE: u32 = 0x8919_3f50;
    /// ChatGatewayRequestIFaceProxy: whisper.
    pub const WHISPER: u32 = 0x5a24_9b1a;
}

/// Locates cmd_dispatch by its RPC ID (once at +0x149 in the 2026-03-10 build, twice in the
/// 2026-10-16 build; every hit is in cmd_dispatch).
pub unsafe fn find_cmd_dispatch(base: usize) -> Result<ScanHit, String> {
    unsafe { find_rpc_method(base, rpc::CMD_DISPATCH) }
}

/// Locates an RPC proxy method by the ID constant it loads.
pub unsafe fn find_rpc_method(base: usize, id: u32) -> Result<ScanHit, String> {
    let landmark = id.to_le_bytes();
    unsafe {
        let pe = PeImage::parse(base)?;
        let text = pe
            .section(".text")
            .ok_or_else(|| ".text section not found".to_string())?;
        let refs: Vec<u32> = find_all(pe.section_bytes(text), &landmark)
            .map(|i| text.rva + i as u32)
            .collect();
        if refs.is_empty() {
            return Err(format!("RPC id 0x{:x} not found in .text", id));
        }
        let (begin, end) = pe.unique_function(&refs)?;
        Ok(ScanHit {
            rva: begin,
            detail: format!(
                "{} landmark hit(s) (first 0x{:x}), function 0x{:x}..0x{:x}",
                refs.len(),
                refs[0],
                begin,
                end
            ),
        })
    }
}

/// RVAs of the vtables along cmd_dispatch's global pointer chain: the global holds the
/// `OmegaClientApp`, +0x30 its `OmegaAreaObject`, +0x48 that one's
/// `AreaServerRequestIFaceProxy` (the manager cmd_dispatch is called on). The chat gateway hangs
/// off the same app (see chat_gateway.rs).
#[derive(Clone, Copy, Debug)]
pub struct ChainVtables {
    pub app: u32,
    pub context: u32,
    pub manager: u32,
}

/// Finds the chain's vtables by their RTTI class names.
pub unsafe fn find_chain_vtables(base: usize) -> Result<ChainVtables, String> {
    unsafe {
        let pe = PeImage::parse(base)?;
        Ok(ChainVtables {
            app: pe.find_vtable_by_rtti("OmegaClientApp")?,
            context: pe.find_vtable_by_rtti("OmegaAreaObject")?,
            manager: pe.find_vtable_by_rtti("AreaServerRequestIFaceProxy")?,
        })
    }
}

/// Locates the chat gateway's channel-message handler: entry 0 of the vtable ChatGatewayObject has
/// for its ChatGatewayResponseIFace base (server -> client chat events). Called as
/// `(this, ?, from_sso, channel_id_sso, i32 channel, text_sso)`.
pub unsafe fn find_chat_channel_recv(base: usize) -> Result<ScanHit, String> {
    unsafe {
        let pe = PeImage::parse(base)?;
        let offset = pe.base_class_offset("ChatGatewayObject", "ChatGatewayResponseIFace")?;
        let vtable = pe.find_subobject_vtable("ChatGatewayObject", offset)?;
        let entry = pe
            .vtable_entry(vtable, 0)
            .ok_or_else(|| format!("vtable 0x{:x} entry 0 is not in .text", vtable))?;
        Ok(ScanHit {
            rva: entry,
            detail: format!("ChatGatewayResponseIFace at +{}, vtable 0x{:x}, entry 0", offset, vtable),
        })
    }
}

/// Offsets of every occurrence of `needle` in `hay`.
fn find_all<'a>(hay: &'a [u8], needle: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
    hay.windows(needle.len()).enumerate().filter(move |(_, w)| *w == needle).map(|(i, _)| i)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lays out swtor.exe from disk the way the Windows loader would (headers
    /// plus each section at its RVA) and runs the scanner on it.
    ///
    /// Run with `SWTOR_EXE=<path>` and optionally `EXPECTED_CHAT_RECV=0x...`,
    /// `EXPECTED_CMD_DISPATCH=0x...`, `EXPECTED_CHAIN_VTABLES=0x...,0x...,0x...` (app, context,
    /// manager), `EXPECTED_CHAT_CHANNEL_RECV=0x...`.
    #[test]
    fn finds_chat_recv_in_on_disk_image() {
        let Ok(path) = std::env::var("SWTOR_EXE") else {
            eprintln!("SWTOR_EXE not set; skipping");
            return;
        };
        let data = std::fs::read(&path).expect("read swtor.exe");
        let u16at = |o: usize| u16::from_le_bytes([data[o], data[o + 1]]) as usize;
        let u32at = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap()) as usize;

        let pe = u32at(0x3c);
        let nsec = u16at(pe + 6);
        let optsz = u16at(pe + 20);
        let opt = pe + 24;
        let image_size = u32at(opt + 56);
        let headers_size = u32at(opt + 60);

        let layout = std::alloc::Layout::from_size_align(image_size, 4096).unwrap();
        let image = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!image.is_null());
        let img = unsafe { slice::from_raw_parts_mut(image, image_size) };
        img[..headers_size].copy_from_slice(&data[..headers_size]);
        for i in 0..nsec {
            let s = opt + optsz + 40 * i;
            let vsize = u32at(s + 8);
            let rva = u32at(s + 12);
            let rsize = u32at(s + 16);
            let raw = u32at(s + 20);
            let n = rsize.min(vsize.max(rsize)).min(image_size - rva);
            img[rva..rva + n].copy_from_slice(&data[raw..raw + n]);
        }

        let hit = unsafe { find_chat_recv(image as usize) }.expect("scan should succeed");
        println!("chat_recv scan: rva=0x{:x} ({})", hit.rva, hit.detail);

        let hex = |v: &str| u32::from_str_radix(v.trim().trim_start_matches("0x"), 16).unwrap();
        if let Ok(expected) = std::env::var("EXPECTED_CHAT_RECV") {
            assert_eq!(hit.rva, hex(&expected));
        }

        let started = std::time::Instant::now();
        let hit = unsafe { find_cmd_dispatch(image as usize) }.expect("cmd_dispatch scan should succeed");
        println!("cmd_dispatch scan: rva=0x{:x} ({}) in {:?}", hit.rva, hit.detail, started.elapsed());
        if let Ok(expected) = std::env::var("EXPECTED_CMD_DISPATCH") {
            assert_eq!(hit.rva, hex(&expected));
        }

        let started = std::time::Instant::now();
        let vtables = unsafe { find_chain_vtables(image as usize) }.expect("RTTI scan should succeed");
        println!("chain vtables: {:x?} in {:?}", vtables, started.elapsed());
        if let Ok(expected) = std::env::var("EXPECTED_CHAIN_VTABLES") {
            let expected: Vec<u32> = expected.split(',').map(hex).collect();
            assert_eq!(vec![vtables.app, vtables.context, vtables.manager], expected);
        }
        for (name, id) in [("channel message", rpc::CHANNEL_MESSAGE), ("whisper", rpc::WHISPER)] {
            let hit = unsafe { find_rpc_method(image as usize, id) }.expect("RPC method scan should succeed");
            println!("{name}: rva=0x{:x} ({})", hit.rva, hit.detail);
        }
        let hit = unsafe { find_chat_channel_recv(image as usize) }.expect("channel receive scan should succeed");
        println!("chat_channel_recv: rva=0x{:x} ({})", hit.rva, hit.detail);
        if let Ok(expected) = std::env::var("EXPECTED_CHAT_CHANNEL_RECV") {
            assert_eq!(hit.rva, hex(&expected));
        }
        unsafe { std::alloc::dealloc(image, layout) };
    }
}
