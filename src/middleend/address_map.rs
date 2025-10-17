use crate::frontend::elf::{SectionHeader, SectionData};
use std::collections::HashMap;

/// Represents a memory segment that needs to be loaded into linear memory
#[derive(Debug, Clone)]
pub struct MemorySegment {
    /// Virtual address where this segment should be loaded
    pub vaddr: u64,
    /// Size of the segment in bytes
    pub size: usize,
    /// Data to load (None for BSS - zero-initialized)
    pub data: Option<Vec<u8>>,
    /// Whether this segment is writable
    pub writable: bool,
    /// Whether this segment is executable
    pub executable: bool,
}

/// Maps virtual addresses from the RISC-V binary to WASM linear memory offsets
#[derive(Debug)]
pub struct AddressMap {
    /// Memory segments extracted from the ELF binary
    segments: Vec<MemorySegment>,
    /// Mapping from virtual address to linear memory offset
    vaddr_to_offset: HashMap<u64, u32>,
    /// Base address where program memory starts in WASM linear memory
    /// (We reserve 0x0-0xFFFF for special purposes)
    pub memory_base: u32,
    /// Minimum virtual address across ALL allocated sections (even ones we don't load)
    min_vaddr: u64,
}

impl AddressMap {
    /// Create a new AddressMap with a specified memory base
    pub fn new(memory_base: u32) -> Self {
        Self {
            segments: Vec::new(),
            vaddr_to_offset: HashMap::new(),
            memory_base,
            min_vaddr: 0,
        }
    }

    /// Create an AddressMap from ELF sections
    ///
    /// This extracts .data, .rodata, .bss and other loadable sections
    pub fn from_sections<'a>(elf_file: &crate::frontend::elf::ElfFile<'a>, sections: impl Iterator<Item = SectionHeader<'a>>) -> Self {
        // Start program memory at 0 to allow NULL pointer region to be accessible
        // (though it will be zero-filled and reads will return 0)
        let mut map = Self::new(0);

        // Collect sections into a Vec to enable two-pass processing
        let sections_vec: Vec<_> = sections.collect();

        // First pass: find minimum virtual address
        let sections_min_vaddr = sections_vec
            .iter()
            .filter_map(|section| {
                let (section_addr, section_size, section_flags) = match section {
                    SectionHeader::SectionHeader32(h) => (h.address as u64, h.size as usize, h.flags as u64),
                    SectionHeader::SectionHeader64(h) => (h.address, h.size as usize, h.flags),
                };
                // Only consider allocated sections with non-zero size
                if section_size > 0 && (section_flags & 0x2) != 0 {
                    Some(section_addr)
                } else {
                    None
                }
            })
            .min()
            .unwrap_or(0);

        // Map from virtual address 0 to handle NULL pointers and low addresses
        // This prevents underflow in address translation
        let min_vaddr = 0;

        println!("Sections start at: 0x{:x}, mapping from: 0x{:x}", sections_min_vaddr, min_vaddr);

        // Store min_vaddr in the map
        map.min_vaddr = min_vaddr;

        // Second pass: process sections and create linear mapping
        for section in sections_vec {
            // Get section properties using the internal methods via pattern matching
            let (section_addr, section_size, section_flags) = match section {
                SectionHeader::SectionHeader32(h) => (h.address as u64, h.size as usize, h.flags as u64),
                SectionHeader::SectionHeader64(h) => (h.address, h.size as usize, h.flags),
            };

            let section_name = section.get_name(elf_file).unwrap_or("");

            // Only process sections that should be loaded into memory
            if section_size == 0 {
                continue;
            }

            // Check if section is allocated (SHF_ALLOC flag)
            let is_alloc = (section_flags & 0x2) != 0; // SHF_ALLOC = 0x2
            let is_write = (section_flags & 0x1) != 0; // SHF_WRITE = 0x1
            let is_exec = (section_flags & 0x4) != 0;  // SHF_EXECINSTR = 0x4

            if !is_alloc {
                continue;
            }

            // Determine if this is a data or BSS section
            let is_bss = section_name.contains("bss");
            let is_data = section_name.contains("data") || section_name.contains("rodata");
            let is_text = section_name.contains("text");

            if !is_bss && !is_data && !is_text {
                // Skip sections we don't care about
                continue;
            }

            // Calculate linear offset: (vaddr - min_vaddr) + memory_base
            // This maintains a 1:1 mapping from virtual address space to linear memory
            let linear_offset = (section_addr - min_vaddr) as u32 + map.memory_base;

            println!("Loading section '{}' at vaddr=0x{:x}, size=0x{:x}, offset=0x{:x} (vaddr range: 0x{:x}-0x{:x})",
                     section_name, section_addr, section_size, linear_offset,
                     section_addr, section_addr + section_size as u64 - 1);

            // Extract section data
            let section_data = if is_bss {
                // BSS is zero-initialized, no data to copy
                None
            } else {
                // Get actual data from section
                let raw = section.raw_data(elf_file);
                if raw.is_empty() {
                    println!("  Warning: Section '{}' has no data!", section_name);
                    None
                } else {
                    println!("  Extracted {} bytes from section '{}'", raw.len(), section_name);
                    Some(raw.to_vec())
                }
            };

            // Create memory segment
            let segment = MemorySegment {
                vaddr: section_addr,
                size: section_size,
                data: section_data,
                writable: is_write,
                executable: is_exec,
            };

            // Map virtual address to linear memory offset
            map.vaddr_to_offset.insert(section_addr, linear_offset);

            map.segments.push(segment);
        }

        map
    }

    /// Translate a virtual address to a linear memory offset
    pub fn vaddr_to_linear(&self, vaddr: u64) -> Option<u32> {
        // Find the segment containing this virtual address
        for segment in &self.segments {
            if vaddr >= segment.vaddr && vaddr < segment.vaddr + segment.size as u64 {
                // Get the base offset for this segment
                let segment_base = self.vaddr_to_offset.get(&segment.vaddr)?;
                let offset_in_segment = (vaddr - segment.vaddr) as u32;
                return Some(segment_base + offset_in_segment);
            }
        }
        None
    }

    /// Initialize WASM linear memory with data from segments
    ///
    /// Returns a vector of (offset, data) pairs to be loaded into WASM memory
    pub fn get_memory_initializers(&self) -> Vec<(u32, Vec<u8>)> {
        let mut initializers = Vec::new();

        for segment in &self.segments {
            if let Some(data) = &segment.data {
                if let Some(&offset) = self.vaddr_to_offset.get(&segment.vaddr) {
                    // Pad data to match segment size if needed
                    // (Some sections have larger in-memory size than file size)
                    let mut padded_data = data.clone();
                    if padded_data.len() < segment.size {
                        padded_data.resize(segment.size, 0);
                    }
                    initializers.push((offset, padded_data));
                }
            } else {
                // BSS sections - zero-initialized
                if let Some(&offset) = self.vaddr_to_offset.get(&segment.vaddr) {
                    let zero_data = vec![0u8; segment.size];
                    initializers.push((offset, zero_data));
                }
            }
        }

        initializers
    }

    /// Get the total size of linear memory needed (in bytes)
    pub fn required_memory_size(&self) -> u32 {
        let mut max_offset = self.memory_base;

        for segment in &self.segments {
            if let Some(&offset) = self.vaddr_to_offset.get(&segment.vaddr) {
                let segment_end = offset + segment.size as u32;
                if segment_end > max_offset {
                    max_offset = segment_end;
                }
            }
        }

        // Round up to page size (64KB)
        ((max_offset + 0xFFFF) & !0xFFFF)
    }

    /// Get the number of WASM pages needed (each page is 64KB)
    pub fn required_pages(&self) -> u32 {
        self.required_memory_size() / (64 * 1024)
    }

    /// Get all memory segments
    pub fn segments(&self) -> &[MemorySegment] {
        &self.segments
    }

    /// Get the minimum virtual address across all allocated sections
    /// This is the offset that needs to be subtracted from RISC-V addresses
    /// to get WASM linear memory offsets
    pub fn vaddr_base(&self) -> u64 {
        self.min_vaddr
    }
}

/// Trait for linear memory operations
pub trait LinearMemory {
    /// Load data into linear memory at the specified offset
    fn load(&mut self, offset: u32, data: &[u8]) -> Result<(), String>;

    /// Read data from linear memory at the specified offset
    fn read(&self, offset: u32, len: usize) -> Result<Vec<u8>, String>;

    /// Get the size of linear memory in bytes
    fn size(&self) -> usize;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_map_creation() {
        let map = AddressMap::new(0x10000);
        assert_eq!(map.memory_base, 0x10000);
        assert_eq!(map.segments.len(), 0);
    }

    #[test]
    fn test_vaddr_translation() {
        let mut map = AddressMap::new(0x10000);

        // Add a test segment
        map.segments.push(MemorySegment {
            vaddr: 0x80000000,
            size: 0x1000,
            data: Some(vec![0u8; 0x1000]),
            writable: true,
            executable: false,
        });
        map.vaddr_to_offset.insert(0x80000000, 0x10000);

        // Test translation
        assert_eq!(map.vaddr_to_linear(0x80000000), Some(0x10000));
        assert_eq!(map.vaddr_to_linear(0x80000100), Some(0x10100));
        assert_eq!(map.vaddr_to_linear(0x80001000), None); // Beyond segment
    }

    #[test]
    fn test_memory_size_calculation() {
        let mut map = AddressMap::new(0x10000);

        map.segments.push(MemorySegment {
            vaddr: 0x80000000,
            size: 0x5000, // 20KB
            data: None,
            writable: true,
            executable: false,
        });
        map.vaddr_to_offset.insert(0x80000000, 0x10000);

        // Required size should be aligned to 64KB pages
        // 0x10000 + 0x5000 = 0x15000, rounds up to 0x20000 (128KB = 2 pages)
        assert_eq!(map.required_pages(), 2);
    }
}
