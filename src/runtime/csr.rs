/// RISC-V Control and Status Register (CSR) management
///
/// This module provides runtime support for CSR operations that are called
/// from the native code compiled by Cranelift.

use std::sync::{Arc, Mutex};

/// CSR addresses as defined in RISC-V privileged spec
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum CsrAddress {
    // Vector CSRs
    VStart = 0x008,
    VXSat = 0x009,
    VXRm = 0x00A,
    VCSR = 0x00F,
    VL = 0xC20,
    VType = 0xC21,
    VLenB = 0xC22,

    // Machine Information Registers
    MVendorId = 0xF11,
    MArchId = 0xF12,
    MImpId = 0xF13,
    MHartId = 0xF14,

    // Machine Trap Setup
    MStatus = 0x300,
    MISA = 0x301,
    MIE = 0x304,
    MTVec = 0x305,

    // Machine Trap Handling
    MScratch = 0x340,
    MEPC = 0x341,
    MCause = 0x342,
    MTVal = 0x343,
    MIP = 0x344,

    // Performance Counters
    Cycle = 0xC00,
    Time = 0xC01,
    InstRet = 0xC02,
}

impl CsrAddress {
    /// Try to convert a u16 CSR address to a known CSR
    pub fn from_u16(addr: u16) -> Option<Self> {
        match addr {
            0x008 => Some(CsrAddress::VStart),
            0x009 => Some(CsrAddress::VXSat),
            0x00A => Some(CsrAddress::VXRm),
            0x00F => Some(CsrAddress::VCSR),
            0xC20 => Some(CsrAddress::VL),
            0xC21 => Some(CsrAddress::VType),
            0xC22 => Some(CsrAddress::VLenB),
            0xF11 => Some(CsrAddress::MVendorId),
            0xF12 => Some(CsrAddress::MArchId),
            0xF13 => Some(CsrAddress::MImpId),
            0xF14 => Some(CsrAddress::MHartId),
            0x300 => Some(CsrAddress::MStatus),
            0x301 => Some(CsrAddress::MISA),
            0x304 => Some(CsrAddress::MIE),
            0x305 => Some(CsrAddress::MTVec),
            0x340 => Some(CsrAddress::MScratch),
            0x341 => Some(CsrAddress::MEPC),
            0x342 => Some(CsrAddress::MCause),
            0x343 => Some(CsrAddress::MTVal),
            0x344 => Some(CsrAddress::MIP),
            0xC00 => Some(CsrAddress::Cycle),
            0xC01 => Some(CsrAddress::Time),
            0xC02 => Some(CsrAddress::InstRet),
            _ => None,
        }
    }
}

/// CSR Manager - handles CSR read/write operations at runtime
pub struct CsrManager {
    state: Arc<Mutex<crate::middleend::RiscVState>>,
}

impl CsrManager {
    /// Create a new CSR manager
    pub fn new(state: Arc<Mutex<crate::middleend::RiscVState>>) -> Self {
        Self { state }
    }

    /// Read a CSR value
    pub fn read(&self, csr: CsrAddress) -> u64 {
        let state = self.state.lock().unwrap();

        match csr {
            // Vector CSRs
            CsrAddress::VL => state.csr.vl,
            CsrAddress::VType => state.csr.vtype,
            CsrAddress::VStart => state.csr.vstart,
            CsrAddress::VLenB => state.csr.vlenb,
            CsrAddress::VXSat => 0, // TODO: Implement vector fixed-point saturation
            CsrAddress::VXRm => 0,  // TODO: Implement vector fixed-point rounding mode
            CsrAddress::VCSR => 0,  // TODO: Implement vector control/status

            // Machine CSRs
            CsrAddress::MStatus => state.csr.mstatus,
            CsrAddress::MTVec => state.csr.mtvec,
            CsrAddress::MEPC => state.csr.mepc,
            CsrAddress::MCause => state.csr.mcause,

            // Read-only CSRs
            CsrAddress::MVendorId => 0, // Non-commercial implementation
            CsrAddress::MArchId => 0x8000000000000000 | (1 << 20), // RV64I
            CsrAddress::MImpId => 1,                               // Implementation ID
            CsrAddress::MHartId => 0,                              // Hardware thread ID
            CsrAddress::MISA => {
                // MISA: RV64IMAFDC_Zicsr_Zifencei_V
                let mut misa = 0x8000000000000000u64; // RV64
                misa |= 1 << 0;  // A - Atomic
                misa |= 1 << 2;  // C - Compressed
                misa |= 1 << 3;  // D - Double-precision float
                misa |= 1 << 5;  // F - Single-precision float
                misa |= 1 << 8;  // I - Base integer ISA
                misa |= 1 << 12; // M - Integer multiply/divide
                misa |= 1 << 21; // V - Vector extension
                misa
            }

            // Performance counters (TODO: implement actual counting)
            CsrAddress::Cycle => 0,
            CsrAddress::Time => 0,
            CsrAddress::InstRet => 0,

            // Trap handling
            CsrAddress::MIE => 0,
            CsrAddress::MIP => 0,
            CsrAddress::MScratch => 0,
            CsrAddress::MTVal => 0,
        }
    }

    /// Write a CSR value
    pub fn write(&mut self, csr: CsrAddress, value: u64) {
        let mut state = self.state.lock().unwrap();

        match csr {
            // Vector CSRs
            CsrAddress::VL => state.csr.vl = value,
            CsrAddress::VType => state.csr.vtype = value,
            CsrAddress::VStart => state.csr.vstart = value,
            CsrAddress::VLenB => {
                // VLenB is read-only, but we allow setting it for configuration
                state.csr.vlenb = value;
            }
            CsrAddress::VXSat => { /* TODO: Implement */ }
            CsrAddress::VXRm => { /* TODO: Implement */ }
            CsrAddress::VCSR => { /* TODO: Implement */ }

            // Machine CSRs
            CsrAddress::MStatus => state.csr.mstatus = value,
            CsrAddress::MTVec => state.csr.mtvec = value,
            CsrAddress::MEPC => state.csr.mepc = value,
            CsrAddress::MCause => state.csr.mcause = value,

            // Read-only CSRs - ignore writes
            CsrAddress::MVendorId
            | CsrAddress::MArchId
            | CsrAddress::MImpId
            | CsrAddress::MHartId
            | CsrAddress::MISA => { /* Read-only */ }

            // Performance counters - ignore writes (read-only in user mode)
            CsrAddress::Cycle | CsrAddress::Time | CsrAddress::InstRet => { /* Read-only */ }

            // Trap handling
            CsrAddress::MIE => { /* TODO: Implement interrupt enable */ }
            CsrAddress::MIP => { /* TODO: Implement interrupt pending */ }
            CsrAddress::MScratch => { /* TODO: Implement scratch register */ }
            CsrAddress::MTVal => { /* TODO: Implement trap value */ }
        }
    }

    /// CSR read-and-write (CSRRW)
    pub fn read_write(&mut self, csr: CsrAddress, new_value: u64) -> u64 {
        let old_value = self.read(csr);
        self.write(csr, new_value);
        old_value
    }

    /// CSR read-and-set (CSRRS)
    pub fn read_set(&mut self, csr: CsrAddress, mask: u64) -> u64 {
        let old_value = self.read(csr);
        if mask != 0 {
            self.write(csr, old_value | mask);
        }
        old_value
    }

    /// CSR read-and-clear (CSRRC)
    pub fn read_clear(&mut self, csr: CsrAddress, mask: u64) -> u64 {
        let old_value = self.read(csr);
        if mask != 0 {
            self.write(csr, old_value & !mask);
        }
        old_value
    }

    /// VSETVLI - Set vector length based on AVL and VTYPE
    ///
    /// Returns the new VL value
    pub fn vsetvli(&mut self, avl: u64, vtype_immediate: u64) -> u64 {
        let mut state = self.state.lock().unwrap();

        // Parse VTYPE immediate
        let vsew = (vtype_immediate >> 3) & 0b111; // SEW[5:3]
        let vlmul = vtype_immediate & 0b111; // LMUL[2:0]

        // Calculate VLMAX based on SEW and LMUL
        let sew_bytes = 1 << (vsew + 3); // 8, 16, 32, 64, 128, 256, 512, 1024 bits
        let vlen = state.csr.vlenb * 8; // VLEN in bits

        // LMUL calculation
        let lmul_float = match vlmul {
            0b000 => 1.0,   // LMUL=1
            0b001 => 2.0,   // LMUL=2
            0b010 => 4.0,   // LMUL=4
            0b011 => 8.0,   // LMUL=8
            0b101 => 0.125, // LMUL=1/8
            0b110 => 0.25,  // LMUL=1/4
            0b111 => 0.5,   // LMUL=1/2
            _ => 1.0,       // Reserved
        };

        let vlmax = ((vlen as f64) * lmul_float / (sew_bytes as f64 * 8.0)) as u64;

        // Calculate VL
        let new_vl = if avl <= vlmax {
            avl
        } else {
            vlmax
        };

        // Update CSRs
        state.csr.vl = new_vl;
        state.csr.vtype = vtype_immediate;
        state.csr.vstart = 0; // Reset vstart

        new_vl
    }

    /// VSETIVLI - Set vector length with immediate AVL
    pub fn vsetivli(&mut self, avl_immediate: u64, vtype_immediate: u64) -> u64 {
        self.vsetvli(avl_immediate & 0x1F, vtype_immediate) // 5-bit immediate
    }

    /// VSETVL - Set vector length based on AVL from register
    pub fn vsetvl(&mut self, avl: u64, vtype_value: u64) -> u64 {
        self.vsetvli(avl, vtype_value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_csr_address_conversion() {
        assert_eq!(CsrAddress::from_u16(0xC20), Some(CsrAddress::VL));
        assert_eq!(CsrAddress::from_u16(0xC21), Some(CsrAddress::VType));
        assert_eq!(CsrAddress::from_u16(0x300), Some(CsrAddress::MStatus));
    }

    #[test]
    fn test_csr_read_write() {
        let state = Arc::new(Mutex::new(crate::middleend::RiscVState::default()));
        let mut csr_mgr = CsrManager::new(state);

        // Write and read VL
        csr_mgr.write(CsrAddress::VL, 42);
        assert_eq!(csr_mgr.read(CsrAddress::VL), 42);

        // Test read-write operation
        let old_val = csr_mgr.read_write(CsrAddress::VL, 100);
        assert_eq!(old_val, 42);
        assert_eq!(csr_mgr.read(CsrAddress::VL), 100);
    }

    #[test]
    fn test_csr_set_clear() {
        let state = Arc::new(Mutex::new(crate::middleend::RiscVState::default()));
        let mut csr_mgr = CsrManager::new(state);

        // Set bits
        csr_mgr.write(CsrAddress::MStatus, 0b1010);
        let old_val = csr_mgr.read_set(CsrAddress::MStatus, 0b0101);
        assert_eq!(old_val, 0b1010);
        assert_eq!(csr_mgr.read(CsrAddress::MStatus), 0b1111);

        // Clear bits
        let old_val = csr_mgr.read_clear(CsrAddress::MStatus, 0b1100);
        assert_eq!(old_val, 0b1111);
        assert_eq!(csr_mgr.read(CsrAddress::MStatus), 0b0011);
    }

    #[test]
    fn test_vsetvli() {
        let state = Arc::new(Mutex::new(crate::middleend::RiscVState::default()));
        let mut csr_mgr = CsrManager::new(state);

        // VSETVLI with SEW=32, LMUL=1
        let vtype = 0b000_010_000; // SEW=32 (010), LMUL=1 (000)
        let vl = csr_mgr.vsetvli(16, vtype);

        // With VLEN=2048, SEW=32, LMUL=1: VLMAX = 2048/32 = 64
        // AVL=16 <= VLMAX, so VL=16
        assert_eq!(vl, 16);
        assert_eq!(csr_mgr.read(CsrAddress::VL), 16);
    }

    #[test]
    fn test_read_only_csrs() {
        let state = Arc::new(Mutex::new(crate::middleend::RiscVState::default()));
        let mut csr_mgr = CsrManager::new(state);

        // Try to write to read-only CSR
        csr_mgr.write(CsrAddress::MVendorId, 0xDEADBEEF);
        assert_eq!(csr_mgr.read(CsrAddress::MVendorId), 0); // Should remain 0

        // MISA should have expected flags
        let misa = csr_mgr.read(CsrAddress::MISA);
        assert_ne!(misa, 0);
        assert!(misa & (1 << 8) != 0); // I extension
        assert!(misa & (1 << 21) != 0); // V extension
    }
}
