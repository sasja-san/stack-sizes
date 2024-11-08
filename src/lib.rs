//! Library to parse stack usage information ([`.stack_sizes`]) emitted by LLVM
//!
//! [`.stack_sizes`]: https://llvm.org/docs/CodeGenerator.html#emitting-function-stack-size-information

// #![deny(rust_2018_idioms)]
// #![deny(missing_docs)]
// #![deny(warnings)]

#![allow(unused_imports)]

use core::u16;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io::Cursor,
    vec,
};

use anyhow::{anyhow, bail};
use byteorder::{ReadBytesExt, LE};
use xmas_elf::{
    header,
    sections::SectionData,
    symbol_table::{Entry, Type},
    ElfFile,
};











/// Functions found after analyzing an executable
#[derive(Clone, Debug)]
pub struct Functions {
    /// Whether the addresses of these functions are 32-bit or 64-bit
    pub have_32_bit_addresses: bool,

    /// "undefined" symbols, symbols that need to be dynamically loaded
    pub undefined: HashSet<String>,

    /// "defined" symbols, symbols with known locations (addresses)
    pub defined: BTreeMap<u64, Function>,
}











/// A symbol that represents a function (subroutine)
#[derive(Clone, Debug)]
pub struct Function {
    /// The (mangled) name of the function and its aliases
    pub names: Vec<String>,
    /// The size of this subroutine in bytes
    pub size: u64,
    /// The stack usage of the function in bytes
    pub stack: Option<u64>,
}












// is this symbol a tag used to delimit code / data sections within a subroutine?
fn is_tag(name: &str) -> bool {
    name == "$a" || name == "$t" || name == "$d" || {
        (name.starts_with("$a.") || name.starts_with("$d.") || name.starts_with("$t."))
            && name.splitn(2, '.').nth(1).unwrap().parse::<u64>().is_ok()
    }
}





















fn process_symtab_obj<'a, E>(
    entries: &[E],
    elf: &ElfFile,
) -> anyhow::Result<
    (
        BTreeMap<u16, BTreeMap<u64, HashSet<String>>>,
        BTreeMap<u32, u16>,
    )
>
where
    E: Entry,
{
    let mut names: BTreeMap<u16, BTreeMap<u64, HashSet<String>>> = BTreeMap::new();
    let mut shndxs: BTreeMap<u32, u16> = BTreeMap::new();

    for (entry, i) in entries.iter().zip(0..) {
        let name = entry.get_name(elf);
        let shndx = entry.shndx();
        let addr = entry.value() & !1; // clear the thumb bit
        let ty = entry.get_type();

        if shndx != 0 {
            shndxs.insert(i, shndx);
        }

        if ty == Ok(Type::Func)
            || (ty == Ok(Type::NoType)
                && name
                    .map(|name| !name.is_empty() && !is_tag(name))
                    .unwrap_or(false))
        {
            let name = name.map_err(anyhow::Error::msg)?;

            names
                .entry(shndx)
                .or_default()
                .entry(addr)
                .or_default()
                .insert(name.to_string());
        }
    }

    Ok((names, shndxs))
}





















/// Parses an *input* (AKA relocatable) object file (`.o`) and returns a list of symbols and their
/// stack usage
pub fn analyze_object(obj: Vec<u8>) -> anyhow::Result<HashMap<String, u64>> 
{
    let elf = ElfFile::new(&obj).map_err(anyhow::Error::msg)?;

    if elf.header.pt2.type_().as_type() != header::Type::Relocatable {
        bail!("object file is not relocatable")
    }

    // shndx -> (address -> [symbol-name])
    let mut is_64_bit = false;
    let (shndx2names, symtab2shndx) = match elf
        .find_section_by_name(".symtab")
        .ok_or_else(|| anyhow!("`.symtab` section not found"))?
        .get_data(&elf)
    {
        Ok(SectionData::SymbolTable32(entries)) => process_symtab_obj(entries, &elf)?,

        Ok(SectionData::SymbolTable64(entries)) => {
            is_64_bit = true;
            process_symtab_obj(entries, &elf)?
        }

        _ => bail!("malformed .symtab section"),
    };

    let mut sizes: HashMap<String, u64> = HashMap::new();
    let mut sections = elf.section_iter();
    while let Some(section) = sections.next() {
        if section.get_name(&elf) == Ok(".stack_sizes") {
            let mut stack_sizes = Cursor::new(section.raw_data(&elf));

            // next section should be `.rel.stack_sizes` or `.rela.stack_sizes`
            // XXX should we check the section name?
            let relocs: Vec<_> = match sections
                .next()
                .and_then(|section| section.get_data(&elf).ok())
            {
                Some(SectionData::Rel32(rels)) if !is_64_bit => rels
                    .iter()
                    .map(|rel| rel.get_symbol_table_index())
                    .collect(),

                Some(SectionData::Rela32(relas)) if !is_64_bit => relas
                    .iter()
                    .map(|rel| rel.get_symbol_table_index())
                    .collect(),

                Some(SectionData::Rel64(rels)) if is_64_bit => rels
                    .iter()
                    .map(|rel| rel.get_symbol_table_index())
                    .collect(),

                Some(SectionData::Rela64(relas)) if is_64_bit => relas
                    .iter()
                    .map(|rel| rel.get_symbol_table_index())
                    .collect(),

                _ => bail!("expected a section with relocation information after `.stack_sizes`"),
            };

            for index in relocs {
                let addr = if is_64_bit 
                {
                    stack_sizes.read_u64::<LE>()?
                }
                else 
                {
                    u64::from(stack_sizes.read_u32::<LE>()?)
                };

                let stack = leb128::read::unsigned(&mut stack_sizes).unwrap();

                let shndx = symtab2shndx[&index];
                let entries: &BTreeMap<u64, HashSet<String>> = shndx2names
                    .get(&(shndx as u16))
                    .unwrap_or_else(|| panic!("section header with index {} not found", shndx));

                {
                    /*
                    assert!(sizes
                        .insert(
                            *entries
                                .get(&addr)
                                .unwrap_or_else(|| panic!(
                                    "symbol with address {} not found at section {} ({:?})",
                                    addr, shndx, entries
                                ))
                                .iter()
                                .next()
                                .unwrap()
                                .to_string()
                            ,
                            stack
                        )
                        .is_none());
                    */

                    let _e0: Option<&HashSet<String>> = entries.get(&addr);
                    let _e1: &HashSet<String>         = _e0.unwrap_or_else(|| panic!(
                                                            "symbol with address {} not found at section {} ({:?})",
                                                            addr, shndx, entries
                                                        ));
                    let _e2: String = _e1.iter().next().unwrap().to_string();
                    let _s: u64 = stack;

                    // inserting into a hashmap returns None if the value is new
                    // returns Some(x) where x is the old value that was replaced.
                    assert!( sizes.insert(_e2, _s).is_none() );
                }
            }

            if stack_sizes.position() != stack_sizes.get_ref().len() as u64 {
                bail!(
                    "the number of relocations doesn't match the number of `.stack_sizes` entries"
                );
            }
        }
    }

    Ok(sizes)
}















fn process_symtab_exec<E>(
    entries: &[E],
    elf_bytes: Vec<u8>
) -> anyhow::Result< ( HashSet<String>, BTreeMap<u64, Function> ) >
where
    E: Entry + core::fmt::Debug,
{
    let elf_clone                                     = elf_bytes.clone();
    let elf:               ElfFile                    = ElfFile::new(&elf_clone).unwrap();
    let mut defined:       BTreeMap<u64, Function>    = BTreeMap::new();
    let mut maybe_aliases: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    let mut undefined:     HashSet<String>            = HashSet::new();

    for entry in entries {
        let ty = entry.get_type();
        let value = entry.value();
        let size = entry.size();
        let name = entry.get_name(&elf);

        if ty == Ok(Type::Func) {
            let name = name.map_err(anyhow::Error::msg)?;

            if value == 0 && size == 0 
            {
                undefined.insert(name.to_string());
            }
            else
            {
                defined
                    .entry(value)
                    .or_insert(Function {
                        names: vec![],
                        size,
                        stack: None,
                    })
                    .names
                    .push(name.to_string());
            }
        }
        else if ty == Ok(Type::NoType)
        {
            if let Ok(name) = name 
            {
                if !is_tag(name)
                {
                    maybe_aliases.entry(value).or_insert(vec![]).push(name.to_string());
                }
            }
        }
    }

    for (value, alias) in maybe_aliases
    {
        // try with the thumb bit both set and clear
        if let Some(sym) = defined.get_mut(&(value | 1))
        {
            sym.names.extend(alias);
        }
        else if let Some(sym) = defined.get_mut(&(value & !1))
        {
            sym.names.extend(alias);
        }
    }

    Ok((undefined, defined))
}












/// Parses an executable ELF file and returns a list of functions and their stack usage
pub fn analyze_executable(elf_bytes: Vec<u8>) -> anyhow::Result<Functions> {
    let elf = ElfFile::new(&elf_bytes).map_err(anyhow::Error::msg)?;

    let mut have_32_bit_addresses = false;
    let (undefined, mut defined) = if let Some(section) = elf.find_section_by_name(".symtab") {
        match section.get_data(&elf).map_err(anyhow::Error::msg)? 
        {
            SectionData::SymbolTable32(entries) =>
            {
                have_32_bit_addresses = true;
                process_symtab_exec(entries, elf_bytes.clone())?
            }

            SectionData::SymbolTable64(entries) => process_symtab_exec(entries, elf_bytes.clone())?,
            _ => bail!("malformed .symtab section"),
        }
    } else {
        (HashSet::new(), BTreeMap::new())
    };

    if let Some(stack_sizes) = elf.find_section_by_name(".stack_sizes") {
        let data = stack_sizes.raw_data(&elf);
        let end = data.len() as u64;
        let mut cursor = Cursor::new(data);

        while cursor.position() < end {
            let address = if have_32_bit_addresses {
                u64::from(cursor.read_u32::<LE>()?)
            } else {
                cursor.read_u64::<LE>()?
            };
            let stack = leb128::read::unsigned(&mut cursor)?;

            // NOTE try with the thumb bit both set and clear
            if let Some(sym) = defined.get_mut(&(address | 1)) {
                sym.stack = Some(stack);
            } else if let Some(sym) = defined.get_mut(&(address & !1)) {
                sym.stack = Some(stack);
            } else {
                unreachable!()
            }
        }
    }

    Ok(Functions {
        have_32_bit_addresses,
        defined,
        undefined,
    })
}


