use crate::{debugger::catch_syscall, mem, syscall::SyscallStack};
#[allow(unused)]
use gimli::{
    self,
    read::{AttributeValue, AttrsIter, DieReference, EvaluationResult},
    DebugLineOffset, Dwarf, EndianSlice, Reader, RunTimeEndian,
};
use nix::{
    sys::wait::{waitpid, WaitPidFlag, WaitStatus},
    unistd::Pid,
};
use object::{
    Object, ObjectSection, ObjectSymbol, RelocationTarget, SymbolIndex, SymbolKind, SymbolScope,
};
use once_cell::sync::OnceCell;
use proc_maps::MapRange;
use std::{
    borrow::{self, Cow},
    fs, io,
};
use symbolic::{
    common::Name,
    demangle::{Demangle, DemangleOptions},
};

pub trait SymbolTrait {
    fn address(&self) -> u64;
    fn name(&self) -> &str;
    fn size(&self) -> u64;
    fn scope(&self) -> SymbolScope;
    fn symbol_index(&self) -> SymbolIndex;
    fn addend(&self) -> Option<i64>;
    fn set_addend(&mut self, addend: i64);
}

#[derive(Debug, Clone)]
pub struct FunctionInfo {
    address: u64,
    addend: Option<i64>,
    name: String,
    size: u64,
    scope: SymbolScope,
    symbol_index: SymbolIndex,
}

impl SymbolTrait for FunctionInfo {
    fn address(&self) -> u64 {
        self.address
    }

    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn scope(&self) -> SymbolScope {
        self.scope
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn symbol_index(&self) -> SymbolIndex {
        self.symbol_index
    }

    fn addend(&self) -> Option<i64> {
        self.addend
    }

    fn set_addend(&mut self, addend: i64) {
        self.addend = Some(addend);
    }
}

#[derive(Debug, Clone)]
pub struct VariableInfo {
    address: u64,
    addend: Option<i64>,
    name: String,
    size: u64,
    scope: SymbolScope,
    symbol_index: SymbolIndex,
}

impl SymbolTrait for VariableInfo {
    fn address(&self) -> u64 {
        self.address
    }

    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn scope(&self) -> SymbolScope {
        self.scope
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn symbol_index(&self) -> SymbolIndex {
        self.symbol_index
    }

    fn addend(&self) -> Option<i64> {
        self.addend
    }

    fn set_addend(&mut self, addend: i64) {
        self.addend = Some(addend);
    }
}

impl VariableInfo {
    pub fn is_included(&self, map: &MapRange, base_addr: u64) -> bool {
        let map_offset = map.offset as u64;
        let map_size = map.size() as u64;
        let map_start = map.start() as u64;

        let base_diff = map_start - base_addr;
        let var_offset = if self.address > base_diff {
            self.address - base_diff + map_offset
        } else {
            self.address
        };
        (map_offset <= var_offset) && (var_offset < (map_offset + map_size))
    }
}

pub trait MiscSymbolTrait {
    fn kind(&self) -> SymbolKind;
}

#[derive(Debug, Clone)]
pub struct MiscSymbol {
    address: u64,
    name: String,
    size: u64,
    scope: SymbolScope,
    symbol_index: SymbolIndex,
    addend: Option<i64>,
    kind: SymbolKind,
}

impl SymbolTrait for MiscSymbol {
    fn address(&self) -> u64 {
        self.address
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn scope(&self) -> SymbolScope {
        self.scope
    }

    fn symbol_index(&self) -> SymbolIndex {
        self.symbol_index
    }

    fn addend(&self) -> Option<i64> {
        self.addend
    }

    fn set_addend(&mut self, addend: i64) {
        self.addend = Some(addend)
    }
}

impl MiscSymbolTrait for MiscSymbol {
    fn kind(&self) -> SymbolKind {
        self.kind
    }
}

static FILE_MMAP: OnceCell<memmap2::Mmap> = OnceCell::new();
static OBJECT: OnceCell<object::File> = OnceCell::new();
static DWARF_COW: OnceCell<Dwarf<Cow<[u8]>>> = OnceCell::new();
static DWARF: OnceCell<Dwarf<EndianSlice<RunTimeEndian>>> = OnceCell::new();

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

    let dwarf_cow = get_dwarf_cow(&obj).unwrap();
    DWARF_COW.set(dwarf_cow).unwrap();
    let dwarf_cow = DWARF_COW.get().unwrap();

    let dwarf = get_dwarf(&dwarf_cow, endian);
    DWARF.set(dwarf).unwrap();
}

#[derive(Debug)]
pub struct TdbDebugInfo {
    pub filename: String,
    pub fn_info_vec: Vec<FunctionInfo>,
    pub var_info_vec: Vec<VariableInfo>,
    pub misc_symbol_vec: Vec<MiscSymbol>,
    pub mmap_info_vec: Vec<MapRange>,
    pub base_addr: u64,
    pub target_pid: Pid,
    object_ref: &'static OnceCell<object::File<'static>>,
    dwarf_ref: Option<&'static OnceCell<Dwarf<EndianSlice<'static, RunTimeEndian>>>>,
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
    pub fn init(filename: &str, pid: Pid, syscall_stack: &mut SyscallStack) -> (Self, WaitStatus) {
        init_global_objects(filename);
        let obj_static: &'static OnceCell<object::File> = &OBJECT;
        let object = obj_static.get().unwrap();
        let dwarf_static: &'static OnceCell<Dwarf<EndianSlice<RunTimeEndian>>> = &DWARF;

        let mut fn_info_vec = Self::get_elf_fn_info(object);
        let mut var_info_vec = Self::get_elf_var_info(object);
        let mut misc_symbol_vec = Self::get_misc_symbol_info(object);

        let (mmap_info_vec, status) = Self::get_mmap_info_vec(pid, filename, syscall_stack);

        let mut base_addr = u64::MAX;
        for m in &mmap_info_vec {
            if (m.start() as u64) < base_addr {
                base_addr = m.start() as u64;
            }
        }

        let mut reloc_info_vec = Vec::new();
        for (apply_for, reloc) in object.dynamic_relocations().unwrap() {
            match reloc.target() {
                RelocationTarget::Absolute => {
                    let target_symbol_value = apply_for;
                    let target_symbol = Self::find_target_symbol_from_rel_info(
                        target_symbol_value,
                        &mut var_info_vec,
                    );
                    if let Some(sym) = target_symbol {
                        sym.set_addend(reloc.addend());
                    }
                }
                RelocationTarget::Symbol(idx) => {
                    if let Some(sym) = Self::find_target_symbol_from_index(idx, &mut fn_info_vec) {
                        sym.set_addend(reloc.addend());
                    }
                    if let Some(sym) = Self::find_target_symbol_from_index(idx, &mut var_info_vec) {
                        sym.set_addend(reloc.addend());
                    }
                    if let Some(sym) =
                        Self::find_target_symbol_from_index(idx, &mut misc_symbol_vec)
                    {
                        sym.set_addend(reloc.addend());
                    }
                }
                RelocationTarget::Section(_idx) => {
                    unimplemented!("RelocationTarget::Section detected, unimplemented yet!");
                }
                _ => panic!("Invalid RelocationTarget"),
            }
            reloc_info_vec.push((apply_for, reloc));
        }

        (
            Self {
                filename: filename.to_string(),
                fn_info_vec,
                var_info_vec,
                misc_symbol_vec,
                mmap_info_vec,
                base_addr,
                target_pid: pid,
                object_ref: obj_static,
                dwarf_ref: Some(dwarf_static),
            },
            status,
        )
    }

    pub fn get_breakpoint_offset(&self, bp_symbol_name: &str) -> Option<u64> {
        for f in &self.fn_info_vec {
            if f.name == bp_symbol_name {
                return Some(f.address);
            }
        }
        None
    }

    fn get_elf_fn_info(object: &object::File) -> Vec<FunctionInfo> {
        let mut fn_info = Vec::new();
        for sym in object.symbols() {
            if sym.kind() == object::SymbolKind::Text {
                let name = Name::from(sym.name().unwrap());
                let name = name.try_demangle(DemangleOptions::name_only());
                fn_info.push(FunctionInfo {
                    name: name.to_string(),
                    address: sym.address(),
                    size: sym.size(),
                    scope: sym.scope(),
                    symbol_index: sym.index(),
                    addend: None,
                });
            }
        }
        fn_info.sort_by(|a, b| a.address.cmp(&b.address));
        fn_info
    }

    fn get_elf_var_info(object: &object::File) -> Vec<VariableInfo> {
        let mut var_info = Vec::new();
        for sym in object.symbols() {
            if sym.kind() == object::SymbolKind::Data {
                var_info.push(VariableInfo {
                    name: String::from(sym.name().unwrap()),
                    address: sym.address(),
                    size: sym.size(),
                    scope: sym.scope(),
                    symbol_index: sym.index(),
                    addend: None,
                });
            }
        }
        var_info.sort_by(|a, b| a.address.cmp(&b.address));
        var_info
    }

    fn get_misc_symbol_info(object: &object::File) -> Vec<MiscSymbol> {
        let mut misc_symbol_info = Vec::new();
        for sym in object.symbols() {
            match sym.kind() {
                SymbolKind::Text | SymbolKind::Data | SymbolKind::Null | SymbolKind::Unknown => {
                    continue
                }
                _ => misc_symbol_info.push(MiscSymbol {
                    address: sym.address(),
                    name: String::from(sym.name().unwrap()),
                    size: sym.size(),
                    scope: sym.scope(),
                    symbol_index: sym.index(),
                    addend: None,
                    kind: sym.kind(),
                }),
            }
        }
        misc_symbol_info
    }

    fn get_mmap_info_vec(
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
        for m in &self.mmap_info_vec {
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
        for m in &self.mmap_info_vec {
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
        for m in &self.mmap_info_vec {
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
        symbol_vec: &mut Vec<impl SymbolTrait>,
    ) -> Option<&mut dyn SymbolTrait> {
        for sym in symbol_vec {
            if target_symbol_value == sym.address() {
                return Some(sym);
            }
        }
        None
    }

    fn find_target_symbol_from_index(
        index: SymbolIndex,
        symbol_vec: &mut Vec<impl SymbolTrait>,
    ) -> Option<&mut dyn SymbolTrait> {
        for sym in symbol_vec {
            if index == sym.symbol_index() {
                return Some(sym);
            }
        }
        None
    }

    pub fn get_actual_symbol_address(&self, sym: &impl SymbolTrait) -> Option<u64> {
        for map in &self.mmap_info_vec {
            let filename = map.filename();
            let filename = match filename {
                Some(path) => path.file_name().unwrap().to_str().unwrap(),
                None => "",
            };

            match sym.scope() {
                SymbolScope::Compilation | SymbolScope::Linkage => {
                    let start = map.start() as u64;
                    let offset = map.offset as u64;
                    let size = map.size() as u64;
                    if (offset <= sym.address()) && (sym.address() < offset + size) {
                        let diff = sym.address() - offset;
                        return Some(start + diff);
                    } else {
                        continue;
                    };
                }
                SymbolScope::Dynamic => {
                    if self.filename == filename {
                        let mem_base = self.base_addr;
                        match sym.addend() {
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
                                if (offset <= sym.address()) && (sym.address() < offset + size) {
                                    let diff = sym.address() - offset;
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

    pub fn find_function_in(&self, addr: u64) -> Option<&FunctionInfo> {
        for f in &self.fn_info_vec {
            if let Some(start) = self.get_actual_symbol_address(f) {
                let end = start + f.size;
                if (start <= addr) && (addr < end) {
                    return Some(f);
                }
            }
        }
        None
    }

    // fn get_dwarf_fn_info<R: Reader<Offset = usize>>(
    //     dwarf: &Dwarf<EndianSlice<RunTimeEndian>>,
    //     attrs: &mut AttrsIter<R>,
    // ) -> FunctionInfo {
    //     let mut offset = 0;
    //     let mut name = String::new();

    //     while let Some(attr) = attrs.next().unwrap() {
    //         match attr.name() {
    //             gimli::DW_AT_low_pc => {
    //                 offset = Self::get_dwarf_fn_offset(&attr.value()) as u64;
    //             }
    //             gimli::DW_AT_name => {
    //                 name = Self::get_dwarf_fn_name(dwarf, &attr.value());
    //             }
    //             _ => continue,
    //         }
    //     }

    //     FunctionInfo { name, offset }
    // }

    // fn get_dwarf_fn_offset<R: Reader<Offset = usize>>(val: &AttributeValue<R>) -> usize {
    //     match val {
    //         AttributeValue::Addr(offset) => offset.to_owned() as usize,
    //         _ => panic!("bad type!"),
    //     }
    // }

    // fn get_dwarf_fn_name<R: Reader<Offset = usize>>(
    //     dwarf: &Dwarf<EndianSlice<RunTimeEndian>>,
    //     val: &AttributeValue<R>,
    // ) -> String {
    //     match val {
    //         AttributeValue::DebugStrRef(doffset) => {
    //             let debug_str = dwarf.debug_str;
    //             let s = debug_str
    //                 .get_str(doffset.to_owned())
    //                 .unwrap()
    //                 .to_string_lossy()
    //                 .into_owned();
    //             s
    //         }
    //         _ => panic!("bad type!"),
    //     }
    // }
}

#[allow(unused)]
pub fn dump_debug_info(filename: &str) {
    let file = fs::File::open(filename).unwrap();
    let mmap = unsafe { memmap2::Mmap::map(&file).unwrap() };
    let object = object::File::parse(&*mmap).unwrap();
    let endian = if object.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };

    let dwarf_cow = get_dwarf_cow(&object).unwrap();
    let dwarf = get_dwarf(&dwarf_cow, endian);

    let mut iter = dwarf.units();
    while let Some(header) = iter.next().unwrap() {
        println!(
            "Unit at <.debug_info+0x{:x}>",
            header.offset().as_debug_info_offset().unwrap().0
        );
        let unit = dwarf.unit(header).unwrap();

        let mut depth = 0;
        let mut entries = unit.entries();
        while let Some((delta_depth, entry)) = entries.next_dfs().unwrap() {
            depth += delta_depth;
            println!("<{}><{:x}> {}", depth, entry.offset().0, entry.tag());

            let mut attrs = entry.attrs();
            while let Some(attr) = attrs.next().unwrap() {
                let value = attr.value();
                let value = match value {
                    AttributeValue::DebugStrRef(doffset) => {
                        let debug_str = dwarf.debug_str;
                        let s = debug_str
                            .get_str(doffset)
                            .unwrap()
                            .to_string_lossy()
                            .into_owned();
                        s
                    }
                    AttributeValue::String(s) => s.to_string_lossy().into_owned(),
                    AttributeValue::Udata(ud) => format!("0x{:x}", ud),
                    AttributeValue::Flag(f) => format!("{f}"),
                    AttributeValue::FileIndex(i) => {
                        let debug_line = dwarf.debug_line;
                        let program = debug_line
                            .program(DebugLineOffset(0), 8, None, None)
                            .unwrap();
                        let (program, _sequence) = program.sequences().unwrap();
                        let file_names = program.header().file_names();
                        dwarf
                            .attr_string(&unit, file_names[(i - 1) as usize].path_name())
                            .unwrap()
                            .to_string_lossy()
                            .into_owned()
                            .to_string()
                    }
                    AttributeValue::UnitRef(uoffset) => {
                        // let entry = unit.entry(uoffset).unwrap();
                        format!("{:?}", uoffset)
                    }
                    AttributeValue::Data1(d) => format!("Data1(0x{:02x})", d),
                    AttributeValue::Data2(d) => format!("Data2(0x{:04x})", d),
                    AttributeValue::Data4(d) => format!("Data4(0x{:08x})", d),
                    AttributeValue::Data8(d) => format!("Data8(0x{:016x})", d),
                    AttributeValue::Addr(addr) => format!("Addr(0x{:016x})", addr),
                    AttributeValue::Encoding(ate) => ate.static_string().unwrap().to_string(),
                    AttributeValue::Exprloc(e) => {
                        let eval_result = e.evaluation(unit.encoding()).evaluate().unwrap();
                        match eval_result {
                            EvaluationResult::Complete => "Evaluation(Complete)".to_string(),
                            EvaluationResult::RequiresMemory {
                                address,
                                size,
                                space,
                                base_type,
                            } => format!(
                                "Evaluation(RequiresMemory) - address: 0x{:016x}, size: {:02x}, space: {:?}, base_type: {:?}",
                                address, size, space, base_type
                            ),
                            EvaluationResult::RequiresRegister {
                                register, base_type
                            } => format!("Evaluation(RequiresRegister) - register: {:?}, base_type: {:?}", register, base_type),
                            EvaluationResult::RequiresFrameBase => "Evaluation(RequiresFrameBase)".to_string(),
                            EvaluationResult::RequiresTls(tls) => format!("Evaluation(RequiresTls) - tls: {tls}"),
                            EvaluationResult::RequiresCallFrameCfa => "Evaluation(RequiresCallFrameCfa)".to_string(),
                            EvaluationResult::RequiresAtLocation(die_ref) => {
                                match die_ref {
                                    DieReference::UnitRef(uoffset) => format!("Evaluation(RequiresAtLocation) - die_reference: {:?}", uoffset),
                                    DieReference::DebugInfoRef(dioffset) => format!("Evaluation(RequiresAtLocation) - die_reference: {:?}", dioffset),
                                }
                            },
                            EvaluationResult::RequiresEntryValue(e) => format!("Evaluation(RequiresEntryValue) - expr: {:?}", e),
                            EvaluationResult::RequiresParameterRef(uoffset) => format!("Evaluation(RequiresParameterRef) - offset: {:?}", uoffset),
                            _ => "Exprloc".to_string(),
                        }
                    }
                    _ => format!("{:?}", value),
                };
                println!("   {}: {}", attr.name(), value);
            }
        }
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
            None => Ok(borrow::Cow::Borrowed(&[][..])),
        }
    };

    Dwarf::load(&load_section)
}
