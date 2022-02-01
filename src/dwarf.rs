use gimli::{self, Dwarf, EndianSlice, RunTimeEndian};
use object::{Object, ObjectSection};
use std::{borrow, fs::File};

pub fn get_debug_info(filename: &str) {
    let file = File::open(filename).unwrap();
    let mmap = unsafe { memmap::Mmap::map(&file).unwrap() };
    let object = object::File::parse(&*mmap).unwrap();
    let endian = if object.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };
    if let Err(e) = get_debug_info_inner(&object, endian) {
        panic!("get_debug_info_inner error : {e}");
    }
}

fn get_debug_info_inner(
    object: &object::File,
    endian: gimli::RunTimeEndian,
) -> Result<(), gimli::Error> {
    let load_section = |id: gimli::SectionId| -> Result<borrow::Cow<[u8]>, gimli::Error> {
        match object.section_by_name(id.name()) {
            Some(ref section) => Ok(section
                .uncompressed_data()
                .unwrap_or(borrow::Cow::Borrowed(&[][..]))),
            None => Ok(borrow::Cow::Borrowed(&[][..])),
        }
    };

    let dwarf_cow = Dwarf::load(&load_section)?;

    let borrow_section: &dyn for<'a> Fn(&'a borrow::Cow<[u8]>) -> EndianSlice<'a, RunTimeEndian> =
        &|section| EndianSlice::new(&*section, endian);

    let dwarf = dwarf_cow.borrow(&borrow_section);

    let mut iter = dwarf.units();

    while let Some(header) = iter.next()? {
        println!(
            "Unit at <.debug_info+0x{:x}>",
            header.offset().as_debug_info_offset().unwrap().0
        );
        let unit = dwarf.unit(header)?;

        let mut depth = 0;
        let mut entries = unit.entries();
        while let Some((delta_depth, entry)) = entries.next_dfs()? {
            depth += delta_depth;
            println!("<{}><{:x}> {}", depth, entry.offset().0, entry.tag());

            let mut attrs = entry.attrs();
            while let Some(attr) = attrs.next()? {
                println!("   {}: {:?}", attr.name(), attr.value());
            }
        }
    }

    Ok(())
}
