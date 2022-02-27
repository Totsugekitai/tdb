use crate::{debugger::catch_syscall, mem, syscall::SyscallStack};
use gimli::{self, Dwarf, EndianSlice, RunTimeEndian};
use nix::{
    sys::wait::{waitpid, WaitPidFlag, WaitStatus},
    unistd::Pid,
};
use object::{
    Object, ObjectSection, ObjectSymbol, RelocationTarget, SectionIndex, SymbolFlags, SymbolIndex,
    SymbolKind, SymbolScope, SymbolSection,
};
use once_cell::sync::OnceCell;
use proc_maps::MapRange;
use std::{
    borrow::{self, Cow},
    fs, io,
};
// use symbolic::{
//     common::Name,
//     demangle::{Demangle, DemangleOptions},
// };

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Symbol {
    index: SymbolIndex,
    name: String,
    address: u64,
    size: u64,
    kind: SymbolKind,
    section: SymbolSection,
    scope: SymbolScope,
    flags: SymbolFlags<SectionIndex>,
    section_index: Option<SectionIndex>,
    addend: Option<i64>,
}

#[allow(dead_code)]
impl Symbol {
    fn new(o: object::Symbol<'_, '_>, addend: Option<i64>) -> Self {
        Self {
            index: o.index(),
            name: String::from(o.name().unwrap()),
            address: o.address(),
            size: o.size(),
            kind: o.kind(),
            section: o.section(),
            scope: o.scope(),
            flags: o.flags(),
            section_index: o.section_index(),
            addend,
        }
    }

    pub fn index(&self) -> SymbolIndex {
        self.index
    }

    pub fn name(&self) -> &str {
        self.name.as_ref()
    }

    pub fn address(&self) -> u64 {
        self.address
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn kind(&self) -> SymbolKind {
        self.kind
    }

    pub fn section(&self) -> SymbolSection {
        self.section
    }

    pub fn scope(&self) -> SymbolScope {
        self.scope
    }

    pub fn flags(&self) -> SymbolFlags<SectionIndex> {
        self.flags
    }

    pub fn section_index(&self) -> Option<SectionIndex> {
        self.section_index
    }

    pub fn addend(&self) -> Option<i64> {
        self.addend
    }

    fn set_addend(&mut self, addend: i64) {
        self.addend = Some(addend)
    }
}

static FILE_MMAP: OnceCell<memmap2::Mmap> = OnceCell::new();
static OBJECT: OnceCell<object::File> = OnceCell::new();
static DWARF_COW: OnceCell<Option<Dwarf<Cow<[u8]>>>> = OnceCell::new();
static DWARF: OnceCell<Option<Dwarf<EndianSlice<RunTimeEndian>>>> = OnceCell::new();

fn init_global_objects(filename: &str) {
    let file = fs::File::open(filename).unwrap();
    let map = unsafe { memmap2::Mmap::map(&file).unwrap() };
    FILE_MMAP.set(map).unwrap();
    let map = FILE_MMAP.get().unwrap();

    OBJECT.set(object::File::parse(&**map).unwrap()).unwrap();
    let obj = OBJECT.get().unwrap();

    let endian = if obj.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };

    if let Ok(dwarf_cow) = get_dwarf_cow(obj) {
        DWARF_COW.set(Some(dwarf_cow)).unwrap();
        let dwarf_cow = DWARF_COW.get().unwrap().as_ref().unwrap();

        let dwarf = get_dwarf(dwarf_cow, endian);
        DWARF.set(Some(dwarf)).unwrap();
    } else {
        DWARF_COW.set(None).unwrap();
        DWARF.set(None).unwrap();
    }
}

#[derive(Debug)]
pub struct TdbDebugInfo {
    filename: String,
    mmaps: Vec<MapRange>,
    symbols: Vec<Symbol>,
    base_addr: u64,
    target_pid: Pid,
}

pub trait TdbMapRangeTrait {
    fn is_included(&self, actual_addr: u64) -> bool;
}

impl TdbMapRangeTrait for MapRange {
    fn is_included(&self, actual_addr: u64) -> bool {
        let start = self.start() as u64;
        let size = self.size() as u64;
        (start <= actual_addr) && (actual_addr < start + size)
    }
}

impl TdbDebugInfo {
    pub fn filename(&self) -> &str {
        &self.filename
    }

    pub fn base_addr(&self) -> u64 {
        self.base_addr
    }

    pub fn target_pid(&self) -> Pid {
        self.target_pid
    }

    pub fn mmaps(&self) -> &[MapRange] {
        &self.mmaps
    }

    pub fn symbols(&self) -> &[Symbol] {
        &self.symbols
    }

    fn new(filename: &str, pid: Pid) -> Self {
        init_global_objects(filename);

        Self {
            filename: filename.to_string(),
            symbols: Vec::new(),
            mmaps: Vec::new(),
            base_addr: 0,
            target_pid: pid,
        }
    }

    pub fn init(filename: &str, pid: Pid, syscall_stack: &mut SyscallStack) -> (Self, WaitStatus) {
        let mut debug_info = Self::new(filename, pid);

        let (mmaps, status) = Self::get_mmaps(pid, filename, syscall_stack);
        debug_info.mmaps = mmaps;

        let symbols = debug_info.get_symbols();
        debug_info.symbols = symbols;

        let mut base_addr = u64::MAX;
        for m in &debug_info.mmaps {
            if (m.start() as u64) < base_addr {
                base_addr = m.start() as u64;
            }
        }
        debug_info.base_addr = base_addr;

        (debug_info, status)
    }

    fn get_symbols(&self) -> Vec<Symbol> {
        let mut symbols = Vec::new();

        for s in OBJECT.get().unwrap().symbols() {
            let addend = self.get_addend();
            let new_symbol = Symbol::new(s, addend);
            symbols.push(new_symbol);
        }
        symbols
    }

    fn get_addend(&self) -> Option<i64> {
        for (apply_to, reloc) in OBJECT.get().unwrap().dynamic_relocations().unwrap() {
            match reloc.target() {
                RelocationTarget::Absolute => {
                    if Self::find_target_symbol_from_rel_info(apply_to, &self.symbols).is_some() {
                        return Some(reloc.addend());
                    }
                }
                RelocationTarget::Symbol(idx) => {
                    if Self::find_target_symbol_from_index(idx, &self.symbols).is_some() {
                        return Some(reloc.addend());
                    }
                    if Self::find_target_symbol_from_index(idx, &self.symbols).is_some() {
                        return Some(reloc.addend());
                    }
                    if Self::find_target_symbol_from_index(idx, &self.symbols).is_some() {
                        return Some(reloc.addend());
                    }
                }
                RelocationTarget::Section(_idx) => {
                    unimplemented!("RelocationTarget::Section detected, unimplemented yet!");
                }
                _ => panic!("Invalid RelocationTarget"),
            }
        }
        None
    }

    pub fn get_breakpoint_offset(&self, bp_symbol_name: &str) -> Option<u64> {
        for f in self.symbols() {
            if f.name == bp_symbol_name {
                return Some(f.address);
            }
        }
        None
    }

    fn get_mmaps(
        pid: Pid,
        filename: &str,
        syscall_stack: &mut SyscallStack,
    ) -> (Vec<MapRange>, WaitStatus) {
        loop {
            let wait_options = WaitPidFlag::from_bits(
                WaitPidFlag::WCONTINUED.bits() | WaitPidFlag::WUNTRACED.bits(),
            );
            let status = waitpid(pid, wait_options).unwrap();

            if let Ok(m) = mem::get_mmap_info(pid, filename) {
                return (m, status);
            } else {
                catch_syscall(pid, syscall_stack);
            }
        }
    }

    pub fn exec_maps(&self) -> Result<Vec<&MapRange>, Box<dyn std::error::Error>> {
        let mut exec_maps = Vec::new();
        for m in &self.mmaps {
            if m.is_read() && !m.is_write() && m.is_exec() {
                exec_maps.push(m);
            }
        }
        if !exec_maps.is_empty() {
            Ok(exec_maps)
        } else {
            Err(Box::new(io::Error::new(
                io::ErrorKind::NotFound,
                "exec map not found",
            )))
        }
    }

    pub fn data_maps(&self) -> Result<Vec<&MapRange>, Box<dyn std::error::Error>> {
        let mut data_maps = Vec::new();
        for m in &self.mmaps {
            if m.is_read() && m.is_write() && !m.is_exec() {
                data_maps.push(m);
            }
        }
        if !data_maps.is_empty() {
            Ok(data_maps)
        } else {
            Err(Box::new(io::Error::new(
                io::ErrorKind::NotFound,
                "exec map not found",
            )))
        }
    }

    pub fn rodata_maps(&self) -> Result<Vec<&MapRange>, Box<dyn std::error::Error>> {
        let mut rodata_maps = Vec::new();
        for m in &self.mmaps {
            if m.is_read() && !m.is_write() && !m.is_exec() {
                rodata_maps.push(m);
            }
        }
        if !rodata_maps.is_empty() {
            Ok(rodata_maps)
        } else {
            Err(Box::new(io::Error::new(
                io::ErrorKind::NotFound,
                "rodata map not found",
            )))
        }
    }

    fn find_target_symbol_from_rel_info(
        target_symbol_value: u64,
        symbols: &[Symbol],
    ) -> Option<&Symbol> {
        for sym in symbols {
            if target_symbol_value == sym.address {
                return Some(sym);
            }
        }
        None
    }

    fn find_target_symbol_from_index(index: SymbolIndex, symbol_vec: &[Symbol]) -> Option<&Symbol> {
        for sym in symbol_vec {
            if index == sym.index {
                return Some(sym);
            }
        }
        None
    }

    pub fn get_actual_symbol_address(&self, sym: &Symbol) -> Option<u64> {
        for map in &self.mmaps {
            let filename = map.filename();
            let filename = match filename {
                Some(path) => path.file_name().unwrap().to_str().unwrap(),
                None => "",
            };

            match sym.scope {
                SymbolScope::Compilation | SymbolScope::Linkage => {
                    let start = map.start() as u64;
                    let offset = map.offset as u64;
                    let size = map.size() as u64;
                    if (offset <= sym.address) && (sym.address < offset + size) {
                        let diff = sym.address - offset;
                        return Some(start + diff);
                    } else {
                        continue;
                    };
                }
                SymbolScope::Dynamic => {
                    if self.filename() == filename {
                        let mem_base = self.base_addr;
                        match sym.addend {
                            Some(addend) => {
                                let actual = if addend >= 0 {
                                    mem_base + addend as u64
                                } else {
                                    mem_base - (addend.abs() as u64)
                                };
                                return Some(actual);
                            }
                            None => {
                                let start = map.start() as u64;
                                let offset = map.offset as u64;
                                let size = map.size() as u64;
                                if (offset <= sym.address) && (sym.address < offset + size) {
                                    let diff = sym.address - offset;
                                    return Some(start + diff);
                                } else {
                                    continue;
                                };
                            }
                        };
                    } else {
                        continue;
                    }
                }
                SymbolScope::Unknown => continue,
            }
        }
        None
    }

    pub fn find_function_in(&self, actual_addr: u64) -> Option<&Symbol> {
        for f in &self.symbols {
            if let Some(start) = self.get_actual_symbol_address(f) {
                let end = start + f.size;
                if (start <= actual_addr) && (actual_addr < end) {
                    return Some(f);
                }
            }
        }
        None
    }
}

fn get_dwarf<'a>(
    dwarf_cow: &'a Dwarf<Cow<'a, [u8]>>,
    endian: gimli::RunTimeEndian,
) -> Dwarf<EndianSlice<'a, RunTimeEndian>> {
    let borrow_section: &dyn for<'bs> Fn(
        &'bs borrow::Cow<[u8]>,
    ) -> EndianSlice<'bs, RunTimeEndian> = &|section| EndianSlice::new(&*section, endian);

    dwarf_cow.borrow(&borrow_section)
}

fn get_dwarf_cow<'a>(object: &'a object::File) -> Result<Dwarf<Cow<'a, [u8]>>, gimli::Error> {
    let load_section = |id: gimli::SectionId| -> Result<borrow::Cow<[u8]>, gimli::Error> {
        match object.section_by_name(id.name()) {
            Some(ref section) => Ok(section
                .uncompressed_data()
                .unwrap_or(borrow::Cow::Borrowed(&[][..]))),
            //None => Ok(borrow::Cow::Borrowed(&[][..])),
            None => Err(gimli::Error::NoEntryAtGivenOffset),
        }
    };

    Dwarf::load(&load_section)
}
