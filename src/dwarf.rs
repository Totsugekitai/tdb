use gimli::{self, Dwarf, EndianSlice, RunTimeEndian};
use object::{Object, ObjectSection};
use std::{
    borrow::{self, Cow},
    fs::File,
};

// #[derive(Debug)]
// pub struct ExecSegmentInfo {
//     base: usize,
//     len: usize,
// }

// #[derive(Debug)]
// pub struct DataSegmentInfo {
//     base: usize,
//     len: usize,
// }

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
                println!("   {}: {:?}", attr.name(), attr.value());
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
