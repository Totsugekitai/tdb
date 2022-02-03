use gimli::{
    self,
    read::{AttributeValue, DieReference, EvaluationResult},
    DebugLineOffset, Dwarf, EndianSlice, RunTimeEndian,
};
use object::{Object, ObjectSection};
use std::{
    borrow::{self, Cow},
    fs::File,
};

pub fn get_debug_info(filename: &str) {
    let file = File::open(filename).unwrap();
    let mmap = unsafe { memmap::Mmap::map(&file).unwrap() };
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
                        String::from(format!("{s}"))
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
                        format!(
                            "{}",
                            dwarf
                                .attr_string(&unit, file_names[(i - 1) as usize].path_name())
                                .unwrap()
                                .to_string_lossy()
                                .into_owned()
                        )
                    }
                    AttributeValue::UnitRef(uoffset) => {
                        // let entry = unit.entry(uoffset).unwrap();
                        format!("{:?}", uoffset)
                    }
                    AttributeValue::Data1(d) => format!("Data1(0x{:02x})", d),
                    AttributeValue::Data2(d) => format!("Data2(0x{:04x})", d),
                    AttributeValue::Data4(d) => format!("Data4(0x{:08x})", d),
                    AttributeValue::Data8(d) => format!("Data8(0x{:016x})", d),
                    AttributeValue::Encoding(ate) => format!("{}", ate.static_string().unwrap()),
                    AttributeValue::Exprloc(e) => {
                        let eval_result = e.evaluation(unit.encoding()).evaluate().unwrap();
                        match eval_result {
                            EvaluationResult::Complete => format!("Evaluation(Complete)"),
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
                            EvaluationResult::RequiresFrameBase => format!("Evaluation(RequiresFrameBase)"),
                            EvaluationResult::RequiresTls(tls) => format!("Evaluation(RequiresTls) - tls: {tls}"),
                            EvaluationResult::RequiresCallFrameCfa => format!("Evaluation(RequiresCallFrameCfa)"),
                            EvaluationResult::RequiresAtLocation(die_ref) => {
                                match die_ref {
                                    DieReference::UnitRef(uoffset) => format!("Evaluation(RequiresAtLocation) - die_reference: {:?}", uoffset),
                                    DieReference::DebugInfoRef(dioffset) => format!("Evaluation(RequiresAtLocation) - die_reference: {:?}", dioffset),
                                }
                            },
                            EvaluationResult::RequiresEntryValue(e) => format!("Evaluation(RequiresEntryValue) - expr: {:?}", e),
                            EvaluationResult::RequiresParameterRef(uoffset) => format!("Evaluation(RequiresParameterRef) - offset: {:?}", uoffset),
                            _ => format!("Exprloc"),
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

    Ok(Dwarf::load(&load_section)?)
}
