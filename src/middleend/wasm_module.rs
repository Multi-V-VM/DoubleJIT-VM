use wasmer::{
    imports, wat2wasm, Function, FunctionEnv, FunctionEnvMut, Instance, Module, Store, Value,
    WasmPtr,
};
use std::sync::{Arc, Mutex};

/// RISC-V register file mapped to WASM
/// We use WASM linear memory and locals to represent RISC-V registers
#[derive(Debug, Clone)]
pub struct RiscVState {
    /// General purpose registers x0-x31 (x0 is always 0)
    pub x_regs: [i64; 32],

    /// Floating point registers f0-f31
    pub f_regs: [f64; 32],

    /// Vector registers v0-v31 (represented as memory offsets)
    /// Each vector register is VLEN bits (2048 bits = 256 bytes in our config)
    pub v_regs_offset: u32,

    /// Program counter
    pub pc: u64,

    /// CSRs (Control and Status Registers)
    pub csr: CsrState,

    /// Memory base address in WASM linear memory
    pub memory_base: u32,
}

#[derive(Debug, Clone)]
pub struct CsrState {
    /// Vector CSRs
    pub vstart: u64,
    pub vtype: u64,
    pub vl: u64,
    pub vlenb: u64,  // VLEN/8 = 256 bytes

    /// Standard CSRs
    pub mstatus: u64,
    pub mtvec: u64,
    pub mepc: u64,
    pub mcause: u64,
}

impl Default for RiscVState {
    fn default() -> Self {
        Self {
            x_regs: [0; 32],
            f_regs: [0.0; 32],
            v_regs_offset: 0x10000, // Vector registers start at 64KB offset
            pc: 0,
            csr: CsrState {
                vstart: 0,
                vtype: 0,
                vl: 0,
                vlenb: 256, // 2048 bits / 8 = 256 bytes
                mstatus: 0,
                mtvec: 0,
                mepc: 0,
                mcause: 0,
            },
            memory_base: 0,
        }
    }
}

/// WasmModule wraps a Wasmer instance and provides RISC-V execution environment
pub struct WasmModule {
    pub store: Store,
    pub instance: Instance,
    pub state: Arc<Mutex<RiscVState>>,
}

impl WasmModule {
    /// Create a new WASM module for RISC-V execution
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let mut store = Store::default();
        let state = Arc::new(Mutex::new(RiscVState::default()));

        // Build the WASM module with memory and helper functions
        let wasm_bytes = Self::build_base_module()?;
        let module = Module::new(&store, wasm_bytes)?;

        // Create function environment
        let env = FunctionEnv::new(&mut store, state.clone());

        // Create imports for syscall and I/O
        let import_object = imports! {
            "env" => {
                "syscall" => Function::new_typed_with_env(
                    &mut store,
                    &env,
                    Self::syscall_handler
                ),
                "debug_print" => Function::new_typed_with_env(
                    &mut store,
                    &env,
                    Self::debug_print_handler
                ),
            }
        };

        let instance = Instance::new(&mut store, &module, &import_object)?;

        Ok(Self {
            store,
            instance,
            state,
        })
    }

    /// Build the base WASM module with memory and infrastructure
    fn build_base_module() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // This creates a base WASM module with:
        // - Linear memory (16MB initial, 256MB max for SV39 address space)
        // - Global variables for RISC-V registers
        // - Helper functions
        let wat = r#"
(module
  ;; Memory: 256 pages initially (16MB), max 4096 pages (256MB) for SV39
  (memory (export "memory") 256 4096)

  ;; Globals for RISC-V register file (x0-x31)
  ;; Note: x0 is always 0, enforced in software
  (global $x0 (mut i64) (i64.const 0))
  (global $x1 (mut i64) (i64.const 0))
  (global $x2 (mut i64) (i64.const 0))
  (global $x3 (mut i64) (i64.const 0))
  (global $x4 (mut i64) (i64.const 0))
  (global $x5 (mut i64) (i64.const 0))
  (global $x6 (mut i64) (i64.const 0))
  (global $x7 (mut i64) (i64.const 0))
  (global $x8 (mut i64) (i64.const 0))
  (global $x9 (mut i64) (i64.const 0))
  (global $x10 (mut i64) (i64.const 0))
  (global $x11 (mut i64) (i64.const 0))
  (global $x12 (mut i64) (i64.const 0))
  (global $x13 (mut i64) (i64.const 0))
  (global $x14 (mut i64) (i64.const 0))
  (global $x15 (mut i64) (i64.const 0))
  (global $x16 (mut i64) (i64.const 0))
  (global $x17 (mut i64) (i64.const 0))
  (global $x18 (mut i64) (i64.const 0))
  (global $x19 (mut i64) (i64.const 0))
  (global $x20 (mut i64) (i64.const 0))
  (global $x21 (mut i64) (i64.const 0))
  (global $x22 (mut i64) (i64.const 0))
  (global $x23 (mut i64) (i64.const 0))
  (global $x24 (mut i64) (i64.const 0))
  (global $x25 (mut i64) (i64.const 0))
  (global $x26 (mut i64) (i64.const 0))
  (global $x27 (mut i64) (i64.const 0))
  (global $x28 (mut i64) (i64.const 0))
  (global $x29 (mut i64) (i64.const 0))
  (global $x30 (mut i64) (i64.const 0))
  (global $x31 (mut i64) (i64.const 0))

  ;; Program counter
  (global $pc (mut i64) (i64.const 0))

  ;; CSRs
  (global $vl (mut i64) (i64.const 0))
  (global $vtype (mut i64) (i64.const 0))
  (global $vstart (mut i64) (i64.const 0))
  (global $vlenb (mut i64) (i64.const 256))

  ;; Execution control and debug
  (global $exit_flag (mut i32) (i32.const 0))
  (global $instr_count (mut i64) (i64.const 0))
  (global $entry_pc (mut i64) (i64.const 0))

  ;; Vector register file base in linear memory (default 64KB)
  ;; We model v0..v31 each as 16 bytes (v128) for SIMD path
  (global $vreg_base (mut i32) (i32.const 65536))

  ;; Import syscall handler
  (import "env" "syscall" (func $syscall (param i64 i64 i64 i64 i64 i64 i64) (result i64)))
  (import "env" "debug_print" (func $debug_print (param i32)))
  ;; CSR runtime helpers
  (import "env" "csr_read_write" (func $csr_read_write (param i32 i64) (result i64)))
  (import "env" "csr_read_set" (func $csr_read_set (param i32 i64) (result i64)))
  (import "env" "csr_read_clear" (func $csr_read_clear (param i32 i64) (result i64)))

  ;; Helper: Sign extend 32-bit to 64-bit
  (func $sign_extend_32 (param $val i32) (result i64)
    local.get $val
    i64.extend_i32_s
  )

  ;; Helper: Zero extend 32-bit to 64-bit
  (func $zero_extend_32 (param $val i32) (result i64)
    local.get $val
    i64.extend_i32_u
  )

  ;; Helper: Translate RISC-V virtual address to linear memory offset (trivial mapping for now)
  (func $vaddr_to_offset (param $vaddr i64) (result i32)
    local.get $vaddr
    i32.wrap_i64
  )

  ;; Helper: Get register value (returns 0 for x0)
  (func $get_reg (export "get_reg") (param $reg i32) (result i64)
    local.get $reg
    i32.const 0
    i32.eq
    if (result i64)
      i64.const 0
      return
    end

    ;; For now, return from memory-mapped register file
    ;; In generated code, we use direct global access
    i64.const 0
  )

  ;; Helper: Set register value (no-op for x0)
  (func $set_reg (export "set_reg") (param $reg i32) (param $val i64)
    local.get $reg
    i32.const 0
    i32.eq
    if
      return
    end

    ;; Match on register number and set the corresponding global
    local.get $reg
    i32.const 1
    i32.eq
    if
      local.get $val
      global.set $x1
      return
    end

    local.get $reg
    i32.const 2
    i32.eq
    if
      local.get $val
      global.set $x2
      return
    end

    local.get $reg
    i32.const 3
    i32.eq
    if
      local.get $val
      global.set $x3
      return
    end

    local.get $reg
    i32.const 4
    i32.eq
    if
      local.get $val
      global.set $x4
      return
    end

    local.get $reg
    i32.const 5
    i32.eq
    if
      local.get $val
      global.set $x5
      return
    end

    local.get $reg
    i32.const 6
    i32.eq
    if
      local.get $val
      global.set $x6
      return
    end

    local.get $reg
    i32.const 7
    i32.eq
    if
      local.get $val
      global.set $x7
      return
    end

    local.get $reg
    i32.const 8
    i32.eq
    if
      local.get $val
      global.set $x8
      return
    end

    local.get $reg
    i32.const 9
    i32.eq
    if
      local.get $val
      global.set $x9
      return
    end

    local.get $reg
    i32.const 10
    i32.eq
    if
      local.get $val
      global.set $x10
      return
    end

    local.get $reg
    i32.const 11
    i32.eq
    if
      local.get $val
      global.set $x11
      return
    end

    local.get $reg
    i32.const 12
    i32.eq
    if
      local.get $val
      global.set $x12
      return
    end

    local.get $reg
    i32.const 13
    i32.eq
    if
      local.get $val
      global.set $x13
      return
    end

    local.get $reg
    i32.const 14
    i32.eq
    if
      local.get $val
      global.set $x14
      return
    end

    local.get $reg
    i32.const 15
    i32.eq
    if
      local.get $val
      global.set $x15
      return
    end

    local.get $reg
    i32.const 16
    i32.eq
    if
      local.get $val
      global.set $x16
      return
    end

    local.get $reg
    i32.const 17
    i32.eq
    if
      local.get $val
      global.set $x17
      return
    end

    local.get $reg
    i32.const 18
    i32.eq
    if
      local.get $val
      global.set $x18
      return
    end

    local.get $reg
    i32.const 19
    i32.eq
    if
      local.get $val
      global.set $x19
      return
    end

    local.get $reg
    i32.const 20
    i32.eq
    if
      local.get $val
      global.set $x20
      return
    end

    local.get $reg
    i32.const 21
    i32.eq
    if
      local.get $val
      global.set $x21
      return
    end

    local.get $reg
    i32.const 22
    i32.eq
    if
      local.get $val
      global.set $x22
      return
    end

    local.get $reg
    i32.const 23
    i32.eq
    if
      local.get $val
      global.set $x23
      return
    end

    local.get $reg
    i32.const 24
    i32.eq
    if
      local.get $val
      global.set $x24
      return
    end

    local.get $reg
    i32.const 25
    i32.eq
    if
      local.get $val
      global.set $x25
      return
    end

    local.get $reg
    i32.const 26
    i32.eq
    if
      local.get $val
      global.set $x26
      return
    end

    local.get $reg
    i32.const 27
    i32.eq
    if
      local.get $val
      global.set $x27
      return
    end

    local.get $reg
    i32.const 28
    i32.eq
    if
      local.get $val
      global.set $x28
      return
    end

    local.get $reg
    i32.const 29
    i32.eq
    if
      local.get $val
      global.set $x29
      return
    end

    local.get $reg
    i32.const 30
    i32.eq
    if
      local.get $val
      global.set $x30
      return
    end

    local.get $reg
    i32.const 31
    i32.eq
    if
      local.get $val
      global.set $x31
      return
    end
  )

  ;; Entry point (will be populated by codegen)
  (func $main (export "main") (result i32)
    i32.const 0
  )
)
"#;

        let wasm_bytes = wat2wasm(wat.as_bytes())?;
        Ok(wasm_bytes.to_vec())
    }

    /// Syscall handler - implements RISC-V syscalls
    fn syscall_handler(
        env: FunctionEnvMut<Arc<Mutex<RiscVState>>>,
        syscall_num: i64,
        arg1: i64,
        arg2: i64,
        arg3: i64,
        arg4: i64,
        arg5: i64,
        arg6: i64,
    ) -> i64 {
        let state = env.data().lock().unwrap();

        // Implement basic syscalls
        match syscall_num {
            93 => {
                // exit
                println!("RISC-V exit({})", arg1);
                arg1 // return exit code
            }
            64 => {
                // write
                println!("RISC-V write(fd={}, buf=0x{:x}, count={})", arg1, arg2, arg3);
                arg3 as i64 // return bytes written
            }
            63 => {
                // read
                println!("RISC-V read(fd={}, buf=0x{:x}, count={})", arg1, arg2, arg3);
                0 // return bytes read
            }
            _ => {
                println!("Unknown syscall: {}", syscall_num);
                -1 // ENOSYS
            }
        }
    }

    /// Debug print handler
    fn debug_print_handler(
        _env: FunctionEnvMut<Arc<Mutex<RiscVState>>>,
        val: i32,
    ) {
        println!("DEBUG: 0x{:08x} ({})", val, val);
    }

    /// Execute the main function
    pub fn execute(&mut self) -> Result<i32, Box<dyn std::error::Error>> {
        let main = self.instance.exports.get_function("main")?;
        let result = main.call(&mut self.store, &[])?;

        match result.first() {
            Some(Value::I32(v)) => Ok(*v),
            _ => Ok(0),
        }
    }

    /// Get a reference to the WASM memory
    pub fn memory(&self) -> Result<wasmer::Memory, Box<dyn std::error::Error>> {
        Ok(self.instance.exports.get_memory("memory")?.clone())
    }

    /// Load data into WASM memory
    pub fn load_memory(&mut self, offset: u32, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let memory = self.memory()?;
        let view = memory.view(&self.store);

        for (i, &byte) in data.iter().enumerate() {
            view.write_u8((offset + i as u32) as u64, byte)?;
        }

        Ok(())
    }

    /// Read from WASM memory
    pub fn read_memory(&self, offset: u32, len: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let memory = self.memory()?;
        let view = memory.view(&self.store);

        let mut data = vec![0u8; len];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = view.read_u8((offset + i as u32) as u64)?;
        }

        Ok(data)
    }
}

impl Default for WasmModule {
    fn default() -> Self {
        Self::new().expect("Failed to create WASM module")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_wasm_module() {
        let module = WasmModule::new();
        assert!(module.is_ok());
    }

    #[test]
    fn test_memory_operations() {
        let mut module = WasmModule::new().unwrap();

        // Write some data
        let data = vec![1, 2, 3, 4, 5];
        module.load_memory(0x1000, &data).unwrap();

        // Read it back
        let read_data = module.read_memory(0x1000, 5).unwrap();
        assert_eq!(data, read_data);
    }
}
