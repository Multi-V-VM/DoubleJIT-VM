use std::{fmt, mem};
use zero::{read, read_array, read_str, Pod};

pub const TYPE_LOOS: u32 = 0x60000000;
pub const TYPE_HIOS: u32 = 0x6fffffff;
pub const TYPE_LOPROC: u32 = 0x70000000;
pub const TYPE_HIPROC: u32 = 0x7fffffff;
pub const TYPE_GNU_RELRO: u32 = TYPE_LOOS + 0x474e552;
pub const SHT_LOOS: u32 = 0x60000000;
pub const SHT_HIOS: u32 = 0x6fffffff;
pub const SHT_LOPROC: u32 = 0x70000000;
pub const SHT_HIPROC: u32 = 0x7fffffff;
pub const SHT_LOUSER: u32 = 0x80000000;
pub const SHT_HIUSER: u32 = 0xffffffff;

#[derive(Debug)]
pub enum ElfError {
    /// The Binary is Malformed SomeWhere
    Malformed(String),
    /// The Binary does not meet requirement
    NotMeet(String),
    /// The Magic is Unknown
    BadMagic(u64),
    /// An IO based error
    #[cfg(feature = "std")]
    IO(io::Error),
    /// Possible Out of User Space Bound Mapping
    AddressError(u64, String),
}

impl From<u64> for ElfError {
    fn from(e: u64) -> Self {
        Self::BadMagic(e)
    }
}
impl From<String> for ElfError {
    fn from(e: String) -> Self {
        Self::Malformed(e)
    }
}
impl From<(u64, String)> for ElfError {
    fn from(e: (u64, String)) -> Self {
        Self::AddressError(e.0, e.1)
    }
}

pub type ParseResult<T> = Result<T, ElfError>;

#[derive(Debug, Clone)]
pub struct ElfFile<'a> {
    pub input: &'a [u8],
    pub header_part1: &'a HeaderPt1,
    pub header_part2: HeaderPt2<'a>,
}
impl<'a> ElfFile<'a> {
    pub fn get_shstr(&self, index: u32) -> ParseResult<&'a str> {
        self.get_shstr_table()
            .map(|shstr_table| read_str(&shstr_table[(index as usize)..]))
    }
    fn get_shstr_table(&self) -> ParseResult<&'a [u8]> {
        let header = self.parse_section_header(self.input, self.header_part2.get_sh_str_index());
        header.map(|h| &self.input[(h.get_offset() as usize)..])
    }

    pub fn section_iter(&self) -> impl Iterator<Item = SectionHeader<'a>> + '_ {
        SectionIter {
            file: self,
            next_index: 0,
        }
    }

    pub fn program_iter(&self) -> impl Iterator<Item = ProgramHeader<'_>> {
        ProgramIter {
            file: self,
            next_index: 0,
        }
    }

    pub fn parse_section_header(
        &self,
        input: &'a [u8],
        index: u16,
    ) -> ParseResult<SectionHeader<'a>> {
        /* From index 0 (SHN_UNDEF) is an error */
        let start = (index as u64 * self.header_part2.get_sh_entry_size() as u64
            + self.header_part2.get_sh_offset() as u64) as usize;
        dbg!(start);
        let end = start + self.header_part2.get_sh_entry_size() as usize;
        Ok(match self.header_part1.get_class() {
            Class::ThirtyTwo => {
                let header = read(&input[start..end]);
                SectionHeader::SectionHeader32(header)
            }
            Class::SixtyFour => {
                let header = read(&input[start..end]);
                SectionHeader::SectionHeader64(header)
            }
            _ => todo!(),
        })
    }
    pub fn parse_program_header(
        &self,
        input: &'a [u8],
        index: u16,
    ) -> ParseResult<ProgramHeader<'a>> {
        if !(index < self.header_part2.get_ph_count()
            && self.header_part2.get_ph_offset() > 0
            && self.header_part2.get_ph_entry_size() > 0)
        {
            return Err(ElfError::Malformed(String::from(
                "No Program Header in the file.",
            )));
        }
        let start = self.header_part2.get_ph_offset() as usize
            + index as usize * self.header_part2.get_ph_entry_size() as usize;
        let end = start + self.header_part2.get_ph_entry_size() as usize;
        match self.header_part1.get_class() {
            Class::ThirtyTwo => Ok(ProgramHeader::ProgramHeader32(read(&input[start..end]))),
            Class::SixtyFour => Ok(ProgramHeader::ProgramHeader64(read(&input[start..end]))),
            _ => unreachable!(),
        }
    }
    pub fn new(input: &'a [u8]) -> ParseResult<Self> {
        let size_part1 = mem::size_of::<HeaderPt1>();
        if input.len() < size_part1 {
            return Err(ElfError::Malformed(String::from(
                "File is shorter than the first ELF header",
            )));
        }
        let header_part1: &'a HeaderPt1 = read(&input[..size_part1]);
        let header_part2 = match header_part1.get_class() {
            Class::ThirtyTwo => HeaderPt2::Header32(read(
                &input[size_part1..size_part1 + mem::size_of::<HeaderPt2_<u32>>()],
            )),
            Class::SixtyFour => HeaderPt2::Header64(read(
                &input[size_part1..size_part1 + mem::size_of::<HeaderPt2_<u64>>()],
            )),
            _ => {
                return Err(ElfError::Malformed(String::from("Invalid ELF Class")));
            }
        };
        Ok(Self {
            input: &input,
            header_part1: header_part1,
            header_part2: header_part2,
        })
    }
    pub fn parse_interpreter(&mut self) -> ParseResult<&str> {
        for ph in self.program_iter() {
            if ph.get_type() == ProgramHeaderType::Interp && ph.get_file_size() != 0 {
                let count = (ph.get_file_size() - 1) as usize;
                let offset = ph.get_offset() as usize;
                return Ok(std::str::from_utf8(&self.input[offset..(offset + count)]).unwrap());
            }
        }
        Err(ElfError::Malformed("No Interp".into()))
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct HeaderPt1 {
    pub magic: [u8; 4],
    pub class: u8,
    pub data: u8,
    pub version: u8,
    pub os_abi: u8,
    // Often also just padding.
    pub abi_version: u8,
    pub padding: [u8; 7],
}
impl fmt::Display for HeaderPt1 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "ELF header:")?;
        writeln!(f, "    magic:            {:?}", self.magic)?;
        writeln!(f, "    class:            {:?}", self.class)?;
        writeln!(f, "    data:             {:?}", self.data)?;
        writeln!(f, "    version:          {:?}", self.version)?;
        writeln!(f, "    os abi:           {:?}", self.os_abi)?;
        writeln!(f, "    abi version:      {:?}", self.abi_version)?;
        writeln!(f, "    padding:          {:?}", self.padding)?;
        Ok(())
    }
}
impl HeaderPt1 {
    pub fn get_class(&self) -> Class {
        match self.class {
            0 => Class::None,
            1 => Class::ThirtyTwo,
            2 => Class::SixtyFour,
            other => Class::Other(other),
        }
    }
    pub fn get_data(&self) -> Data {
        match self.data {
            0 => Data::None,
            1 => Data::LittleEndian,
            2 => Data::BigEndian,
            other => Data::Other(other),
        }
    }
    pub fn get_version(&self) -> Version {
        match self.version {
            0 => Version::None,
            1 => Version::Current,
            other => Version::Other(other),
        }
    }
    pub fn get_os_abi(&self) -> OsAbi {
        match self.os_abi {
            0x00 => OsAbi::SystemV,
            0x01 => OsAbi::HPUX,
            0x02 => OsAbi::NetBSD,
            0x03 => OsAbi::Linux,
            0x04 => OsAbi::GNUHurd,
            0x06 => OsAbi::Solaris,
            0x07 => OsAbi::AIX,
            0x08 => OsAbi::IRIX,
            0x09 => OsAbi::FreeBSD,
            0x0A => OsAbi::Tru64,
            0x0B => OsAbi::NovellModesto,
            0x0C => OsAbi::OpenBSD,
            0x0D => OsAbi::OpenVMS,
            0x0E => OsAbi::NonStopKernel,
            0x0F => OsAbi::AROS,
            0x10 => OsAbi::FenixOS,
            0x11 => OsAbi::NuxiCloudABI,
            0x12 => OsAbi::OpenVOS,
            other => OsAbi::Other(other),
        }
    }
}
unsafe impl Pod for HeaderPt1 {}
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Class {
    None,
    ThirtyTwo,
    SixtyFour,
    OneTwentyEight,
    Other(u8),
}
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Data {
    None,
    LittleEndian,
    BigEndian,
    Other(u8),
}
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Version {
    None,
    Current,
    Other(u8),
}
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum OsAbi {
    SystemV,
    HPUX,
    NetBSD,
    Linux,
    GNUHurd,
    Solaris,
    AIX,
    IRIX,
    FreeBSD,
    Tru64,
    NovellModesto,
    OpenBSD,
    OpenVMS,
    NonStopKernel,
    AROS,
    FenixOS,
    NuxiCloudABI,
    OpenVOS,
    Other(u8),
}
#[derive(Clone, Copy, Debug)]
pub enum HeaderPt2<'a> {
    Header32(&'a HeaderPt2_<u32>),
    Header64(&'a HeaderPt2_<u64>),
}

impl<'a> fmt::Display for HeaderPt2<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "    type:             {:?}", self.get_type())?;
        writeln!(f, "    machine:          {:?}", self.get_machine())?;
        writeln!(f, "    version:          {}", self.get_version())?;
        writeln!(f, "    entry_point:      {}", self.get_entry_point())?;
        writeln!(f, "    ph_offset:        {}", self.get_ph_offset())?;
        writeln!(f, "    sh_offset:        {}", self.get_sh_offset())?;
        writeln!(f, "    flags:            {}", self.get_flags())?;
        writeln!(f, "    header_size:      {}", self.get_header_size())?;
        writeln!(f, "    ph_entry_size:    {}", self.get_ph_entry_size())?;
        writeln!(f, "    ph_count:         {}", self.get_ph_count())?;
        writeln!(f, "    sh_entry_size:    {}", self.get_sh_entry_size())?;
        writeln!(f, "    sh_count:         {}", self.get_sh_count())?;
        writeln!(f, "    sh_str_index:     {}", self.get_sh_str_index())?;
        Ok(())
    }
}
impl<'a> HeaderPt2<'a> {
    pub fn get_size(&self) -> usize {
        match *self {
            HeaderPt2::Header32(_) => mem::size_of::<HeaderPt2_<u32>>(),
            HeaderPt2::Header64(_) => mem::size_of::<HeaderPt2_<u64>>(),
        }
    }
    pub fn get_type(&self) -> Type {
        match *self {
            HeaderPt2::Header32(h) => match h.type_ {
                0 => Type::None,
                1 => Type::Relocatable,
                2 => Type::Executable,
                3 => Type::SharedObject,
                4 => Type::Core,
                x => Type::ProcessorSpecific(x),
            },
            HeaderPt2::Header64(h) => match h.type_ {
                0 => Type::None,
                1 => Type::Relocatable,
                2 => Type::Executable,
                3 => Type::SharedObject,
                4 => Type::Core,
                x => Type::ProcessorSpecific(x),
            },
        }
    }
    pub fn get_machine(&self) -> Machine {
        match *self {
            HeaderPt2::Header32(h) => match h.machine {
                0x04 => Machine::MotorolaM68k,
                0x05 => Machine::MotorolaM88k,
                0x06 => Machine::IntelMCU,
                0x07 => Machine::Intel80860,
                0x08 => Machine::MIPS,
                0x09 => Machine::IBMSystem370,
                0x0A => Machine::MIPSRS3000,
                0x0E => Machine::HPRISC,
                0x13 => Machine::Intel80960,
                0x14 => Machine::PowerPC,
                0x15 => Machine::PowerPC64,
                0x16 => Machine::S390,
                0x17 => Machine::IBMSPU,
                0x24 => Machine::NECV800,
                0x25 => Machine::FujitsuFR20,
                0x26 => Machine::TRWRH32,
                0x27 => Machine::MotorolaRCE,
                0x28 => Machine::ARMv7,
                0x29 => Machine::DigitalAlpha,
                0x2A => Machine::SuperH,
                0x2B => Machine::SPARC9,
                0x2C => Machine::SiemensTriCore,
                0x2D => Machine::ArgonautRISC,
                0x2E => Machine::HitachiH8300,
                0x2F => Machine::HitachiH8300H,
                0x30 => Machine::HitachiH8S,
                0x31 => Machine::HitachiH8500,
                0x32 => Machine::IA64,
                0x33 => Machine::MIPS,
                0x34 => Machine::MotorolaColdFire,
                0x35 => Machine::MotorolaM68HC12,
                0x36 => Machine::FujitsuMMA,
                0x37 => Machine::SiemensPCP,
                0x38 => Machine::SonynCPU,
                0x39 => Machine::DensoNDR1,
                0x3A => Machine::MotorolaStar,
                0x3B => Machine::ToyotaME16,
                0x3C => Machine::ST100,
                0x3D => Machine::TinyJ,
                0x3E => Machine::AMDx64,
                0x8C => Machine::TMS320C6000,
                0xAF => Machine::MCSTElbrus,
                0xB7 => Machine::ARMv8,
                0xF3 => Machine::RISCV,
                0xF7 => Machine::BPF,
                0x101 => Machine::WDC65C816,
                other => Machine::Other(other),
            },
            HeaderPt2::Header64(h) => match h.machine {
                0x04 => Machine::MotorolaM68k,
                0x05 => Machine::MotorolaM88k,
                0x06 => Machine::IntelMCU,
                0x07 => Machine::Intel80860,
                0x08 => Machine::MIPS,
                0x09 => Machine::IBMSystem370,
                0x0A => Machine::MIPSRS3000,
                0x0E => Machine::HPRISC,
                0x13 => Machine::Intel80960,
                0x14 => Machine::PowerPC,
                0x15 => Machine::PowerPC64,
                0x16 => Machine::S390,
                0x17 => Machine::IBMSPU,
                0x24 => Machine::NECV800,
                0x25 => Machine::FujitsuFR20,
                0x26 => Machine::TRWRH32,
                0x27 => Machine::MotorolaRCE,
                0x28 => Machine::ARMv7,
                0x29 => Machine::DigitalAlpha,
                0x2A => Machine::SuperH,
                0x2B => Machine::SPARC9,
                0x2C => Machine::SiemensTriCore,
                0x2D => Machine::ArgonautRISC,
                0x2E => Machine::HitachiH8300,
                0x2F => Machine::HitachiH8300H,
                0x30 => Machine::HitachiH8S,
                0x31 => Machine::HitachiH8500,
                0x32 => Machine::IA64,
                0x33 => Machine::MIPS,
                0x34 => Machine::MotorolaColdFire,
                0x35 => Machine::MotorolaM68HC12,
                0x36 => Machine::FujitsuMMA,
                0x37 => Machine::SiemensPCP,
                0x38 => Machine::SonynCPU,
                0x39 => Machine::DensoNDR1,
                0x3A => Machine::MotorolaStar,
                0x3B => Machine::ToyotaME16,
                0x3C => Machine::ST100,
                0x3D => Machine::TinyJ,
                0x3E => Machine::AMDx64,
                0x8C => Machine::TMS320C6000,
                0xAF => Machine::MCSTElbrus,
                0xB7 => Machine::ARMv8,
                0xF3 => Machine::RISCV,
                0xF7 => Machine::BPF,
                0x101 => Machine::WDC65C816,
                other => Machine::Other(other),
            },
        }
    }
    pub fn get_version(&self) -> u32 {
        match *self {
            HeaderPt2::Header32(h) => h.version,
            HeaderPt2::Header64(h) => h.version,
        }
    }
    pub fn get_entry_point(&self) -> u64 {
        match *self {
            HeaderPt2::Header32(h) => h.entry_point as u64,
            HeaderPt2::Header64(h) => h.entry_point,
        }
    }
    pub fn get_ph_offset(&self) -> u64 {
        match *self {
            HeaderPt2::Header32(h) => h.ph_offset as u64,
            HeaderPt2::Header64(h) => h.ph_offset,
        }
    }
    pub fn get_sh_offset(&self) -> u64 {
        match *self {
            HeaderPt2::Header32(h) => h.sh_offset as u64,
            HeaderPt2::Header64(h) => h.sh_offset,
        }
    }
    pub fn get_flags(&self) -> u32 {
        match *self {
            HeaderPt2::Header32(h) => h.flags,
            HeaderPt2::Header64(h) => h.flags,
        }
    }
    pub fn get_header_size(&self) -> u16 {
        match *self {
            HeaderPt2::Header32(h) => h.header_size,
            HeaderPt2::Header64(h) => h.header_size,
        }
    }
    pub fn get_ph_entry_size(&self) -> u16 {
        match *self {
            HeaderPt2::Header32(h) => h.ph_entry_size,
            HeaderPt2::Header64(h) => h.ph_entry_size,
        }
    }
    pub fn get_ph_count(&self) -> u16 {
        match *self {
            HeaderPt2::Header32(h) => h.ph_count,
            HeaderPt2::Header64(h) => h.ph_count,
        }
    }
    pub fn get_sh_count(&self) -> u16 {
        match *self {
            HeaderPt2::Header32(h) => h.sh_count,
            HeaderPt2::Header64(h) => h.sh_count,
        }
    }
    pub fn get_sh_entry_size(&self) -> u16 {
        match *self {
            HeaderPt2::Header32(h) => h.sh_entry_size,
            HeaderPt2::Header64(h) => h.sh_entry_size,
        }
    }
    pub fn get_sh_str_index(&self) -> u16 {
        match *self {
            HeaderPt2::Header32(h) => h.sh_str_index,
            HeaderPt2::Header64(h) => h.sh_str_index,
        }
    }
}
#[derive(Debug)]
#[repr(C)]
pub struct HeaderPt2_<P> {
    pub type_: u16,
    pub machine: u16,
    pub version: u32,
    pub entry_point: P,
    pub ph_offset: P,
    pub sh_offset: P,
    pub flags: u32,
    pub header_size: u16,
    pub ph_entry_size: u16,
    pub ph_count: u16,
    pub sh_entry_size: u16,
    pub sh_count: u16,
    pub sh_str_index: u16,
}
unsafe impl<P> Pod for HeaderPt2_<P> {}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Type {
    None,
    Relocatable,
    Executable,
    SharedObject,
    Core,
    ProcessorSpecific(u16),
}
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Machine {
    None,
    ATAT,
    Sparc,
    X86,
    MotorolaM68k,
    MotorolaM88k,
    IntelMCU,
    Intel80860,
    MIPS,
    IBMSystem370,
    MIPSRS3000,
    HPRISC,
    Intel80960,
    PowerPC,
    PowerPC64,
    S390,
    IBMSPU,
    NECV800,
    FujitsuFR20,
    TRWRH32,
    MotorolaRCE,
    ARMv7,
    DigitalAlpha,
    SuperH,
    SPARC9,
    SiemensTriCore,
    ArgonautRISC,
    HitachiH8300,
    HitachiH8300H,
    HitachiH8S,
    HitachiH8500,
    IA64,
    MIPSX,
    MotorolaColdFire,
    MotorolaM68HC12,
    FujitsuMMA,
    SiemensPCP,
    SonynCPU,
    DensoNDR1,
    MotorolaStar,
    ToyotaME16,
    ST100,
    TinyJ,
    AMDx64,
    TMS320C6000,
    MCSTElbrus,
    ARMv8,
    RISCV,
    BPF,
    WDC65C816,
    Other(u16),
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum SectionHeaderType {
    /// marks an unused section header
    SectionNull,
    /// information defined by the program
    ProgramBits,
    /// a linker symbol table
    SymbolTable,
    /// a string table
    StringTable,
    /// “Rela” type relocation entries
    RelocationAddendTable,
    /// a symbol hash table
    HashTable,
    /// dynamic linking tables
    DynamicLinkingTable,
    /// note information
    NOTE,
    /// uninitialized space; does not occupy any space in the file
    NoBits,
    /// “Rel” type relocation entries
    RelocationTable,
    /// reserved
    SharedLibrary,
    /// a dynamic loader symbol table
    DynamicSymbolTable,
    /// an array of pointers to initialization functions
    InitializeArray,
    /// an array of pointers to termination functions
    TerminationArray,
    /// an array of pointers to pre-initialization functions
    PreInitializeArray,
    Group,
    SymTabShIndex,
    OsSpecific(u32),
    ProcessorSpecific(u32),
    User(u32),
}

#[derive(Debug, Clone)]
pub struct SectionIter<'b, 'a: 'b> {
    pub file: &'b ElfFile<'a>,
    pub next_index: u16,
}

impl<'b, 'a> Iterator for SectionIter<'b, 'a> {
    type Item = SectionHeader<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let count = self.file.header_part2.get_sh_count();
        if self.next_index >= count {
            return None;
        }

        let result = self
            .file
            .parse_section_header(self.file.input, self.next_index);
        self.next_index += 1;
        result.ok()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SectionHeader<'a> {
    SectionHeader32(&'a SectionHeader_<u32>),
    SectionHeader64(&'a SectionHeader_<u64>),
}

impl<'a> fmt::Display for SectionHeader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Section header:")?;
        writeln!(f, "    name:             {:?}", self.get_name_())?;
        writeln!(f, "    type:             {:?}", self.get_type())?;
        writeln!(f, "    flags:            {:?}", self.get_flags())?;
        writeln!(f, "    address:          {:?}", self.get_address())?;
        writeln!(f, "    offset:           {:?}", self.get_offset())?;
        writeln!(f, "    size:             {:?}", self.get_size())?;
        writeln!(f, "    link:             {:?}", self.get_link())?;
        writeln!(f, "    align:            {:?}", self.get_align())?;
        writeln!(f, "    entry size:       {:?}", self.get_entry_size())?;
        Ok(())
    }
}

impl<'a> SectionHeader<'a> {
    // Note that this function is O(n) in the length of the name.
    pub fn get_name(&self, elf_file: &ElfFile<'a>) -> ParseResult<&'a str> {
        self.get_type().and_then(|typ| match typ {
            SectionHeaderType::NOTE => Err(ElfError::Malformed(String::from(
                "Attempt to get name of null section",
            ))),
            _ => elf_file.get_shstr(self.get_name_()),
        })
    }

    pub fn get_data(&self, elf_file: &ElfFile<'a>) -> ParseResult<SectionData<'a>> {
        macro_rules! array_data {
            ($data32: ident, $data64: ident, $data128: ident) => {{
                let data = self.raw_data(elf_file);
                match elf_file.header_part1.get_class() {
                    Class::ThirtyTwo => SectionData::$data32(read_array(data)),
                    Class::SixtyFour => SectionData::$data64(read_array(data)),
                    Class::OneTwentyEight => SectionData::$data128(read_array(data)),
                    _ => unreachable!(),
                }
            }};
        }

        self.get_type().map(|typ| match typ {
            _ | SectionHeaderType::SectionNull | SectionHeaderType::NoBits => SectionData::Empty,
            SectionHeaderType::ProgramBits
            | SectionHeaderType::SharedLibrary
            | SectionHeaderType::OsSpecific(_)
            | SectionHeaderType::ProcessorSpecific(_)
            | SectionHeaderType::User(_) => SectionData::Undefined(self.raw_data(elf_file)),
            SectionHeaderType::SymbolTable => {
                array_data!(SymbolTable32, SymbolTable64, SymbolTable128)
            }
            SectionHeaderType::DynamicSymbolTable => {
                array_data!(DynSymbolTable32, DynSymbolTable64, DynSymbolTable128)
            }
            SectionHeaderType::StringTable => SectionData::StrArray(self.raw_data(elf_file)),
            SectionHeaderType::InitializeArray
            | SectionHeaderType::TerminationArray
            | SectionHeaderType::PreInitializeArray => {
                array_data!(FnArray32, FnArray64, FnArray128)
            }
            SectionHeaderType::RelocationAddendTable => array_data!(Rela32, Rela64, Rela128),
            SectionHeaderType::RelocationAddendTable => array_data!(Rel32, Rel64, Rel128),
            SectionHeaderType::DynamicLinkingTable => array_data!(Dynamic32, Dynamic64, Dynamic128),
            SectionHeaderType::Group => {
                let data = self.raw_data(elf_file);
                unsafe {
                    let flags: &'a u32 = mem::transmute(&data[0]);
                    let indicies: &'a [u32] = read_array(&data[4..]);
                    SectionData::Group { flags, indicies }
                }
            }
            SectionHeaderType::SymTabShIndex => {
                SectionData::SymTabShIndex(read_array(self.raw_data(elf_file)))
            }
            SectionHeaderType::NOTE => {
                let data = self.raw_data(elf_file);
                match elf_file.header_part1.get_class() {
                    Class::ThirtyTwo => {
                        // TODO: NOTE32 is 4 byte ptr, which require further impl
                        let header: &'a NoteHeader = read(&data[0..12]);
                        let index = &data[12..];
                        SectionData::Note32(header, index)
                    }
                    Class::SixtyFour => {
                        let header: &'a NoteHeader = read(&data[0..12]);
                        let index = &data[12..];
                        SectionData::Note64(header, index)
                    }
                    _ => todo!(),
                }
            }
            SectionHeaderType::HashTable => {
                let data = self.raw_data(elf_file);
                SectionData::HashTable(read(&data[0..12]))
            }
        })
    }
    pub fn raw_data(&self, elf_file: &ElfFile<'a>) -> &'a [u8] {
        assert_ne!(
            self.get_section_type().unwrap(),
            SectionHeaderType::SectionNull
        );
        &elf_file.input[self.get_offset() as usize..(self.get_offset() + self.get_size()) as usize]
    }
    pub fn get_type(&self) -> ParseResult<SectionHeaderType> {
        self.get_section_type()
    }
    fn get_flags(&self) -> u64 {
        match *self {
            SectionHeader::SectionHeader32(h) => h.flags as u64,
            SectionHeader::SectionHeader64(h) => h.flags,
        }
    }
    fn get_name_(&self) -> u32 {
        match *self {
            SectionHeader::SectionHeader32(h) => h.name,
            SectionHeader::SectionHeader64(h) => h.name,
        }
    }
    fn get_address(&self) -> u64 {
        match *self {
            SectionHeader::SectionHeader32(h) => h.address as u64,
            SectionHeader::SectionHeader64(h) => h.address,
        }
    }
    fn get_align(&self) -> u64 {
        match *self {
            SectionHeader::SectionHeader32(h) => h.alignment as u64,
            SectionHeader::SectionHeader64(h) => h.alignment,
        }
    }
    fn get_entry_size(&self) -> u64 {
        match *self {
            SectionHeader::SectionHeader32(h) => h.entry_size as u64,
            SectionHeader::SectionHeader64(h) => h.entry_size,
        }
    }
    fn get_offset(&self) -> u64 {
        match *self {
            SectionHeader::SectionHeader32(h) => h.offset as u64,
            SectionHeader::SectionHeader64(h) => h.offset,
        }
    }
    fn get_size(&self) -> u64 {
        match *self {
            SectionHeader::SectionHeader32(h) => h.size as u64,
            SectionHeader::SectionHeader64(h) => h.size,
        }
    }
    fn get_section_type(&self) -> ParseResult<SectionHeaderType> {
        match *self {
            SectionHeader::SectionHeader32(h) => {
                match h.section_type {
                    0 => Ok(SectionHeaderType::SectionNull),
                    1 => Ok(SectionHeaderType::ProgramBits),
                    2 => Ok(SectionHeaderType::SymbolTable),
                    3 => Ok(SectionHeaderType::StringTable),
                    4 => Ok(SectionHeaderType::RelocationAddendTable),
                    5 => Ok(SectionHeaderType::HashTable),
                    6 => Ok(SectionHeaderType::DynamicLinkingTable),
                    7 => Ok(SectionHeaderType::NOTE),
                    8 => Ok(SectionHeaderType::NoBits),
                    9 => Ok(SectionHeaderType::RelocationTable),
                    10 => Ok(SectionHeaderType::SharedLibrary),
                    11 => Ok(SectionHeaderType::DynamicSymbolTable),
                    // sic.
                    14 => Ok(SectionHeaderType::InitializeArray),
                    15 => Ok(SectionHeaderType::TerminationArray),
                    16 => Ok(SectionHeaderType::PreInitializeArray),
                    17 => Ok(SectionHeaderType::Group),
                    18 => Ok(SectionHeaderType::SymTabShIndex),
                    st if st >= SHT_LOOS && st <= SHT_HIOS => Ok(SectionHeaderType::OsSpecific(st)),
                    st if st >= SHT_LOPROC && st <= SHT_HIPROC => {
                        Ok(SectionHeaderType::ProcessorSpecific(st))
                    }
                    st if st >= SHT_LOUSER && st <= SHT_HIUSER => Ok(SectionHeaderType::User(st)),
                    _ => Err(ElfError::Malformed(String::from("Invalid sh type"))),
                    _ => unreachable!(),
                }
            }
            SectionHeader::SectionHeader64(h) => {
                match h.section_type {
                    0 => Ok(SectionHeaderType::SectionNull),
                    1 => Ok(SectionHeaderType::ProgramBits),
                    2 => Ok(SectionHeaderType::SymbolTable),
                    3 => Ok(SectionHeaderType::StringTable),
                    4 => Ok(SectionHeaderType::RelocationAddendTable),
                    5 => Ok(SectionHeaderType::HashTable),
                    6 => Ok(SectionHeaderType::DynamicLinkingTable),
                    7 => Ok(SectionHeaderType::NOTE),
                    8 => Ok(SectionHeaderType::NoBits),
                    9 => Ok(SectionHeaderType::RelocationTable),
                    10 => Ok(SectionHeaderType::SharedLibrary),
                    11 => Ok(SectionHeaderType::DynamicSymbolTable),
                    // sic.
                    14 => Ok(SectionHeaderType::InitializeArray),
                    15 => Ok(SectionHeaderType::TerminationArray),
                    16 => Ok(SectionHeaderType::PreInitializeArray),
                    17 => Ok(SectionHeaderType::Group),
                    18 => Ok(SectionHeaderType::SymTabShIndex),
                    st if st >= SHT_LOOS && st <= SHT_HIOS => Ok(SectionHeaderType::OsSpecific(st)),
                    st if st >= SHT_LOPROC && st <= SHT_HIPROC => {
                        Ok(SectionHeaderType::ProcessorSpecific(st))
                    }
                    st if st >= SHT_LOUSER && st <= SHT_HIUSER => Ok(SectionHeaderType::User(st)),
                    _ => Err(ElfError::Malformed(String::from("Invalid sh type"))),
                    _ => unreachable!(),
                }
            }
        }
    }
    fn get_link(&self) -> u32 {
        match *self {
            SectionHeader::SectionHeader32(h) => h.link,
            SectionHeader::SectionHeader64(h) => h.link,
        }
    }
    fn get_info(&self) -> u32 {
        match *self {
            SectionHeader::SectionHeader32(h) => h.info,
            SectionHeader::SectionHeader64(h) => h.info,
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SectionHeader_<P> {
    ///	contains the offset, in bytes, to the section name, relative to the start of the section
    /// name string table.
    name: u32,
    /// identifies the section type.
    section_type: u32,
    /// identifies the attributes of the section.
    flags: P,
    /// contains the virtual address of the beginning of the section in memory. If the section is
    /// not allocated to the memory image of the program, this field should be zero.
    address: P,
    /// contains the offset, in bytes, of the beginning of the section contents in the file.
    offset: P,
    /// contains the size, in bytes, of the section. Except for ShtNoBits sections, this is the
    /// amount of space occupied in the file.
    size: P,
    /// contains the section index of an associated section. This field is used for several
    /// purposes, depending on the type of section, as explained in Table 10.
    link: u32,
    /// contains extra information about the section. This field is used for several purposes,
    /// depending on the type of section, as explained in Table 11.
    info: u32,
    /// contains the required alignment of the section. This field must be a power of two.
    alignment: P,
    /// contains the size, in bytes, of each entry, for sections that contain fixed-size entries.
    /// Otherwise, this field contains zero.
    entry_size: P,
}

impl<P> SectionHeader_<P> {}

unsafe impl<P> Pod for SectionHeader_<P> {}

#[derive(Debug, Clone)]
pub enum SectionData<'a> {
    Empty,
    Undefined(&'a [u8]),
    Group { flags: &'a u32, indicies: &'a [u32] },
    StrArray(&'a [u8]),
    FnArray32(&'a [u32]),
    FnArray64(&'a [u64]),
    FnArray128(&'a [u64]),
    SymbolTable32(&'a [Entry32]),
    SymbolTable64(&'a [Entry64]),
    SymbolTable128(&'a [Entry128]),
    DynSymbolTable32(&'a [DynEntry32]),
    DynSymbolTable64(&'a [DynEntry64]),
    DynSymbolTable128(&'a [DynEntry128]),
    SymTabShIndex(&'a [u32]),
    Note32(&'a NoteHeader, &'a [u8]),
    Note64(&'a NoteHeader, &'a [u8]),
    Note128(&'a NoteHeader, &'a [u8]),
    Rela32(&'a [Rela<u32>]),
    Rela64(&'a [Rela<u64>]),
    Rela128(&'a [Rela<u64>]),
    Rel32(&'a [Rel<u32>]),
    Rel64(&'a [Rel<u64>]),
    Rel128(&'a [Rel<u64>]),
    Dynamic32(&'a [Dynamic<u32>]),
    Dynamic64(&'a [Dynamic<u64>]),
    Dynamic128(&'a [Dynamic<u64>]),
    HashTable(&'a HashTable),
}

impl<'a> fmt::Display for SectionData<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SectionData::Empty => writeln!(f, "SectionData::Empty")?,
            SectionData::Undefined(_) => writeln!(f, "SectionData::Undefined")?,
            SectionData::Group { flags, indicies } => writeln!(f, "SectionData::Group")?,
            SectionData::StrArray(_) => writeln!(f, "SectionData::StrArray")?,
            SectionData::FnArray32(_) => writeln!(f, "SectionData::FnArray32")?,
            SectionData::FnArray64(_) => writeln!(f, "SectionData::FnArray64")?,
            SectionData::SymbolTable32(_) => writeln!(f, "SectionData::SymbolTable32")?,
            SectionData::SymbolTable64(_) => writeln!(f, "SectionData::SymbolTable64")?,
            SectionData::DynSymbolTable32(_) => writeln!(f, "SectionData::DynSymbolTable32")?,
            SectionData::DynSymbolTable64(_) => writeln!(f, "SectionData::DynSymbolTable64")?,
            SectionData::SymTabShIndex(_) => writeln!(f, "SectionData::SymTabShIndex")?,
            SectionData::Note64(_, _) => writeln!(f, "SectionData::Note64")?,
            SectionData::Rela32(_) => writeln!(f, "SectionData::Rela32")?,
            SectionData::Rela64(_) => writeln!(f, "SectionData::Rela64")?,
            SectionData::Rel32(_) => writeln!(f, "SectionData::Rel32")?,
            SectionData::Rel64(_) => writeln!(f, "SectionData::Rel64")?,
            SectionData::Dynamic32(_) => writeln!(f, "SectionData::Dynamic32")?,
            SectionData::Dynamic64(_) => writeln!(f, "SectionData::Dynamic64")?,
            SectionData::HashTable(_) => writeln!(f, "SectionData::HashTable")?,
            _ => writeln!(f, "SectionData::Unknown")?,
        }
        Ok(())
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct Dynamic<P>
where
    Tag_<P>: fmt::Debug,
{
    tag: Tag_<P>,
    un: P,
}

unsafe impl<P> Pod for Dynamic<P> where Tag_<P>: fmt::Debug {}

#[derive(Copy, Clone, Debug)]
pub struct Tag_<P>(P);

#[derive(Debug, PartialEq, Eq)]
pub enum Tag<P> {
    Null,
    Needed,
    PltRelSize,
    Pltgot,
    Hash,
    StrTab,
    SymTab,
    Rela,
    RelaSize,
    RelaEnt,
    StrSize,
    SymEnt,
    Init,
    Fini,
    SoName,
    RPath,
    Symbolic,
    Rel,
    RelSize,
    RelEnt,
    PltRel,
    Debug,
    TextRel,
    JmpRel,
    BindNow,
    InitArray,
    FiniArray,
    InitArraySize,
    FiniArraySize,
    RunPath,
    Flags,
    PreInitArray,
    PreInitArraySize,
    SymTabShIndex,
    Flags1,
    OsSpecific(P),
    ProcessorSpecific(P),
}

#[derive(Debug)]
#[repr(C)]
pub struct Rela<P> {
    offset: P,
    info: P,
    addend: P,
}

#[derive(Debug)]
#[repr(C)]
pub struct Rel<P> {
    offset: P,
    info: P,
}

unsafe impl<P> Pod for Rela<P> {}
unsafe impl<P> Pod for Rel<P> {}

#[derive(Debug)]
#[repr(C)]
struct Entry32_ {
    name: u32,
    value: u32,
    size: u32,
    info: u8,
    other: u8,
    shndx: u16,
}

#[derive(Debug)]
#[repr(C)]
struct Entry64_ {
    name: u32,
    info: u8,
    other: u8,
    shndx: u16,
    value: u64,
    size: u64,
}

#[derive(Debug)]
#[repr(C)]
struct Entry128_ {
    name: u32,
    info: u8,
    other: u8,
    shndx: u16,
    value: u128,
    size: u128,
}

unsafe impl Pod for Entry32_ {}
unsafe impl Pod for Entry64_ {}
unsafe impl Pod for Entry128_ {}

#[derive(Debug)]
#[repr(C)]
pub struct Entry32(Entry32_);

#[derive(Debug)]
#[repr(C)]
pub struct Entry64(Entry64_);

#[derive(Debug)]
#[repr(C)]
pub struct Entry128(Entry128_);

unsafe impl Pod for Entry32 {}
unsafe impl Pod for Entry64 {}
unsafe impl Pod for Entry128 {}

#[derive(Debug)]
#[repr(C)]
pub struct DynEntry32(Entry32_);

#[derive(Debug)]
#[repr(C)]
pub struct DynEntry64(Entry64_);

#[derive(Debug)]
#[repr(C)]
pub struct DynEntry128(Entry128_);

unsafe impl Pod for DynEntry32 {}
unsafe impl Pod for DynEntry64 {}
unsafe impl Pod for DynEntry128 {}

#[derive(Copy, Clone, Debug)]
#[repr(u8)]
pub enum Visibility {
    Default = 0,
    Internal = 1,
    Hidden = 2,
    Protected = 3,
}
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct NoteHeader {
    name_size: u32,
    desc_size: u32,
    type_: u32,
}
unsafe impl Pod for NoteHeader {}
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct HashTable {
    bucket_count: u32,
    chain_count: u32,
    first_bucket: u32,
}

#[derive(Debug, Clone)]
pub struct ProgramIter<'b, 'a: 'b> {
    pub file: &'b ElfFile<'a>,
    pub next_index: u16,
}

impl<'b, 'a> Iterator for ProgramIter<'b, 'a> {
    type Item = ProgramHeader<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let count = self.file.header_part2.get_ph_count();
        if self.next_index >= count {
            return None;
        }

        let result = self
            .file
            .parse_program_header(self.file.input, self.next_index);
        self.next_index += 1;
        result.ok()
    }
}
unsafe impl Pod for HashTable {}
#[derive(Debug, Clone, Copy)]
pub enum ProgramHeader<'a> {
    ProgramHeader32(&'a ProgramHeader32),
    ProgramHeader64(&'a ProgramHeader64),
}
impl<'a> fmt::Display for ProgramHeader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Program header:")?;
        writeln!(f, "    type:             {:?}", self.get_type())?;
        writeln!(f, "    flags:            {}", self.get_flags())?;
        writeln!(f, "    offset:           {:#x}", self.get_offset())?;
        writeln!(f, "    virtual address:  {:#x}", self.get_virtual_addr())?;
        writeln!(f, "    physical address: {:#x}", self.get_physical_addr())?;
        writeln!(f, "    file size:        {:#x}", self.get_file_size())?;
        writeln!(f, "    memory size:      {:#x}", self.get_mem_size())?;
        writeln!(f, "    align:            {:#x}", self.get_align())?;
        Ok(())
    }
}
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct ProgramHeader32 {
    pub type_: u32,
    pub offset: u32,
    pub virtual_addr: u32,
    pub physical_addr: u32,
    pub file_size: u32,
    pub mem_size: u32,
    pub flags: u32,
    pub align: u32,
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct ProgramHeader64 {
    pub type_: u32,
    pub flags: u32,
    pub offset: u64,
    pub virtual_addr: u64,
    pub physical_addr: u64,
    pub file_size: u64,
    pub mem_size: u64,
    pub align: u64,
}
unsafe impl Pod for ProgramHeader32 {}
unsafe impl Pod for ProgramHeader64 {}

impl ProgramHeader32 {
    pub fn get_type(&self) -> ParseResult<ProgramHeaderType> {
        match self.type_ {
            0 => Ok(ProgramHeaderType::Null),
            1 => Ok(ProgramHeaderType::Load),
            2 => Ok(ProgramHeaderType::Dynamic),
            3 => Ok(ProgramHeaderType::Interp),
            4 => Ok(ProgramHeaderType::Note),
            5 => Ok(ProgramHeaderType::ShLib),
            6 => Ok(ProgramHeaderType::Phdr),
            7 => Ok(ProgramHeaderType::Tls),
            TYPE_GNU_RELRO => Ok(ProgramHeaderType::GnuRelro),
            t if t >= TYPE_LOOS && t <= TYPE_HIOS => Ok(ProgramHeaderType::OsSpecific(t)),
            t if t >= TYPE_LOPROC && t <= TYPE_HIPROC => {
                Ok(ProgramHeaderType::ProcessorSpecific(t))
            }
            _ => Err(ElfError::Malformed(String::from("Invalid type"))),
        }
    }
    pub fn get_data<'a>(&self, elf: &ElfFile<'a>) -> ParseResult<SegmentData<'a>> {
        self.get_type().map(|typ| match typ {
            ProgramHeaderType::Null => SegmentData::Empty,
            ProgramHeaderType::Dynamic => {
                let data = self.raw_data(elf);
                match elf.header_part1.get_class() {
                    Class::ThirtyTwo => SegmentData::Dynamic32(read_array(data)),
                    Class::SixtyFour => SegmentData::Dynamic64(read_array(data)),
                    Class::OneTwentyEight => SegmentData::Dynamic128(read_array(data)),
                    Class::None | Class::Other(_) => unreachable!(),
                }
            }
            ProgramHeaderType::Load
            | ProgramHeaderType::Interp
            | ProgramHeaderType::ShLib
            | ProgramHeaderType::Phdr
            | ProgramHeaderType::GnuRelro
            | ProgramHeaderType::OsSpecific(_)
            | ProgramHeaderType::ProcessorSpecific(_)
            | ProgramHeaderType::Tls => SegmentData::Undefined(self.raw_data(elf)),
            ProgramHeaderType::Note => todo!(),
        });
        todo!()
    }
    pub fn raw_data<'a>(&self, elf_file: &ElfFile<'a>) -> &'a [u8] {
        assert!(self
            .get_type()
            .map(|typ| typ != ProgramHeaderType::Null)
            .unwrap_or(false));
        &elf_file.input[self.offset as usize..(self.offset + self.file_size) as usize]
    }
}

impl ProgramHeader64 {
    pub fn get_type(&self) -> ParseResult<ProgramHeaderType> {
        match self.type_ {
            0 => Ok(ProgramHeaderType::Null),
            1 => Ok(ProgramHeaderType::Load),
            2 => Ok(ProgramHeaderType::Dynamic),
            3 => Ok(ProgramHeaderType::Interp),
            4 => Ok(ProgramHeaderType::Note),
            5 => Ok(ProgramHeaderType::ShLib),
            6 => Ok(ProgramHeaderType::Phdr),
            7 => Ok(ProgramHeaderType::Tls),
            TYPE_GNU_RELRO => Ok(ProgramHeaderType::GnuRelro),
            t if t >= TYPE_LOOS && t <= TYPE_HIOS => Ok(ProgramHeaderType::OsSpecific(t)),
            t if t >= TYPE_LOPROC && t <= TYPE_HIPROC => {
                Ok(ProgramHeaderType::ProcessorSpecific(t))
            }
            _ => Err(ElfError::Malformed(String::from("Invalid type"))),
        }
    }
    pub fn get_data<'a>(&self, elf: &ElfFile<'a>) -> ParseResult<SegmentData<'a>> {
        self.get_type().map(|typ| match typ {
            ProgramHeaderType::Null => SegmentData::Empty,
            ProgramHeaderType::Dynamic => {
                let data = self.raw_data(elf);
                match elf.header_part1.get_class() {
                    Class::ThirtyTwo => SegmentData::Dynamic32(read_array(data)),
                    Class::SixtyFour => SegmentData::Dynamic64(read_array(data)),
                    Class::OneTwentyEight => SegmentData::Dynamic128(read_array(data)),
                    Class::None | Class::Other(_) => unreachable!(),
                }
            }
            ProgramHeaderType::Load
            | ProgramHeaderType::Interp
            | ProgramHeaderType::ShLib
            | ProgramHeaderType::Phdr
            | ProgramHeaderType::GnuRelro
            | ProgramHeaderType::OsSpecific(_)
            | ProgramHeaderType::ProcessorSpecific(_)
            | ProgramHeaderType::Tls => SegmentData::Undefined(self.raw_data(elf)),
            ProgramHeaderType::Note => todo!(),
        });
        todo!()
    }
    pub fn raw_data<'a>(&self, elf_file: &ElfFile<'a>) -> &'a [u8] {
        assert!(self
            .get_type()
            .map(|typ| typ != ProgramHeaderType::Null)
            .unwrap_or(false));
        &elf_file.input[self.offset as usize..(self.offset + self.file_size) as usize]
    }
}

impl<'a> ProgramHeader<'a> {
    pub fn get_type(&self) -> ProgramHeaderType {
        match *self {
            ProgramHeader::ProgramHeader32(ph) => ph.get_type().unwrap(),
            ProgramHeader::ProgramHeader64(ph) => ph.get_type().unwrap(),
        }
    }

    pub fn get_data(&self, elf_file: &ElfFile<'a>) -> SegmentData<'a> {
        match *self {
            ProgramHeader::ProgramHeader32(ph) => ph.get_data(elf_file).unwrap(),
            ProgramHeader::ProgramHeader64(ph) => ph.get_data(elf_file).unwrap(),
        }
    }
    pub fn get_align(&self) -> u64 {
        match *self {
            ProgramHeader::ProgramHeader32(h) => h.align as u64,
            ProgramHeader::ProgramHeader64(h) => h.align,
        }
    }
    pub fn get_virtual_addr(&self) -> u64 {
        match *self {
            ProgramHeader::ProgramHeader32(h) => h.virtual_addr as u64,
            ProgramHeader::ProgramHeader64(h) => h.virtual_addr,
        }
    }
    pub fn get_physical_addr(&self) -> u64 {
        match *self {
            ProgramHeader::ProgramHeader32(h) => h.physical_addr as u64,
            ProgramHeader::ProgramHeader64(h) => h.physical_addr,
        }
    }
    pub fn get_file_size(&self) -> u64 {
        match *self {
            ProgramHeader::ProgramHeader32(h) => h.file_size as u64,
            ProgramHeader::ProgramHeader64(h) => h.file_size,
        }
    }
    pub fn get_mem_size(&self) -> u64 {
        match *self {
            ProgramHeader::ProgramHeader32(h) => h.mem_size as u64,
            ProgramHeader::ProgramHeader64(h) => h.mem_size as u64,
        }
    }
    pub fn get_offset(&self) -> u64 {
        match *self {
            ProgramHeader::ProgramHeader32(h) => h.offset as u64,
            ProgramHeader::ProgramHeader64(h) => h.offset as u64,
        }
    }
    pub fn physical_addr(&self) -> u64 {
        match *self {
            ProgramHeader::ProgramHeader32(h) => h.physical_addr as u64,
            ProgramHeader::ProgramHeader64(h) => h.physical_addr as u64,
        }
    }
    pub fn virtual_addr(&self) -> u64 {
        match *self {
            ProgramHeader::ProgramHeader32(h) => h.virtual_addr as u64,
            ProgramHeader::ProgramHeader64(h) => h.virtual_addr as u64,
        }
    }
    pub fn get_flags(&self) -> u32 {
        match *self {
            ProgramHeader::ProgramHeader32(h) => h.flags,
            ProgramHeader::ProgramHeader64(h) => h.flags,
        }
    }
}

#[derive(Debug)]
pub enum SegmentData<'a> {
    Empty,
    Undefined(&'a [u8]),
    Dynamic32(&'a [Dynamic<u32>]),
    Dynamic64(&'a [Dynamic<u64>]),
    Dynamic128(&'a [Dynamic<u128>]),
    /// 1 uses 4-byte words, which I'm not sure how to manage.
    /// The pointer is to the start of the name field in the note.
    Note64(&'a NoteHeader, &'a [u8]), /* TODO Interp and Phdr should probably be defined some how, but I can't find the details. */
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ProgramHeaderType {
    Null,
    Load,
    Dynamic,
    Interp,
    Note,
    ShLib,
    Phdr,
    Tls,
    GnuRelro,
    OsSpecific(u32),
    ProcessorSpecific(u32),
}
