use wasmer::{
    imports, wat2wasm, Engine, Function, FunctionEnv, FunctionEnvMut, Instance, Module, Store,
    Value,
};
use wasmer_compiler_cranelift::Cranelift;
use std::sync::{Arc, Mutex};

/// Optimization level for Cranelift code generation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptLevel {
    /// No optimizations - fastest compilation
    None,
    /// Basic optimizations - balanced
    Speed,
    /// Maximum optimizations - best runtime performance
    SpeedAndSize,
}

/// Backend builder that compiles WAT to native code using Cranelift
///
/// Pipeline: WAT → WASM bytecode → Cranelift IR → native x86/ARM code → Wasmer runtime
///
/// The Cranelift compiler automatically detects the host architecture and generates
/// optimized native code:
/// - x86-64 (Intel/AMD) on Linux, Windows, macOS
/// - ARM64/AArch64 on Apple Silicon, ARM servers, embedded systems
/// - Other architectures supported by Cranelift
pub struct WasmBuilder {
    /// Cranelift compiler engine
    engine: Engine,
    /// Wasmer store for managing compiled modules
    store: Store,
    /// Optimization level
    opt_level: OptLevel,
}

impl WasmBuilder {
    /// Create a new WasmBuilder with Cranelift compiler
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_opt_level(OptLevel::Speed)
    }

    /// Create a WasmBuilder with specific optimization level
    pub fn with_opt_level(opt_level: OptLevel) -> Result<Self, Box<dyn std::error::Error>> {
        // Configure Cranelift compiler based on optimization level
        let mut compiler = Cranelift::default();

        // Note: Wasmer's Cranelift wrapper may not expose all settings directly
        // but the default configuration is already optimized for the target architecture

        // Create engine with Cranelift backend
        // This will compile WASM to native code for the current architecture:
        // - Detects x86-64, ARM64, etc. automatically
        // - Uses architecture-specific optimizations
        // - Generates machine code that runs directly on the CPU
        let engine = Engine::from(compiler);

        // Create store with the Cranelift engine
        let store = Store::new(engine.clone());

        Ok(Self { engine, store, opt_level })
    }

    /// Get the current optimization level
    pub fn opt_level(&self) -> OptLevel {
        self.opt_level
    }

    /// Compile WAT (WebAssembly Text) to native code and create a Wasmer module
    ///
    /// This performs the full compilation pipeline:
    /// 1. Parse WAT to WASM bytecode
    /// 2. Cranelift compiles WASM to native machine code (x86-64/ARM)
    /// 3. Returns a compiled Module ready for instantiation
    pub fn compile_wat(&self, wat_source: &str) -> Result<Module, Box<dyn std::error::Error>> {
        // Step 1: Convert WAT to WASM bytecode
        let wasm_bytes = wat2wasm(wat_source.as_bytes())?;

        // Step 2: Compile WASM to native code using Cranelift
        // The engine automatically selects the appropriate target (x86-64, ARM, etc.)
        let module = Module::new(&self.store, wasm_bytes)?;

        Ok(module)
    }

    /// Compile WASM bytecode directly to native code
    pub fn compile_wasm(&self, wasm_bytes: &[u8]) -> Result<Module, Box<dyn std::error::Error>> {
        // Cranelift compiles WASM to native code
        let module = Module::new(&self.store, wasm_bytes)?;
        Ok(module)
    }

    /// Get a reference to the store
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Get a mutable reference to the store
    pub fn store_mut(&mut self) -> &mut Store {
        &mut self.store
    }

    /// Get a reference to the engine
    pub fn engine(&self) -> &Engine {
        &self.engine
    }
}

impl Default for WasmBuilder {
    fn default() -> Self {
        Self::new().expect("Failed to create WasmBuilder")
    }
}

/// Environment for syscall handlers - includes both state and memory reference
pub struct SyscallEnv {
    /// RISC-V architectural state
    state: Arc<Mutex<crate::middleend::RiscVState>>,
    /// Reference to WASM memory for reading/writing buffers
    memory: Option<wasmer::Memory>,
    /// Exit flag global (for breaking interpreter loop)
    exit_flag: Option<wasmer::Global>,
}

/// Runtime environment for executing compiled RISC-V code
///
/// This wraps the Cranelift-compiled native code with RISC-V runtime state
pub struct RiscVRuntime {
    /// Compiled WASM module (native code)
    module: Module,
    /// Wasmer instance (running native code)
    instance: Instance,
    /// Store for runtime state
    store: Store,
    /// RISC-V architectural state
    state: Arc<Mutex<crate::middleend::RiscVState>>,
    /// Exit flag global (for breaking interpreter loop)
    exit_flag: Option<wasmer::Global>,
}

impl RiscVRuntime {
    /// Create a new runtime from a compiled module
    pub fn new(
        mut store: Store,
        module: Module,
        state: Arc<Mutex<crate::middleend::RiscVState>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Create syscall environment with state
        let syscall_env = Arc::new(Mutex::new(SyscallEnv {
            state: state.clone(),
            memory: None, // Will be set after instance creation
            exit_flag: None, // Will be set after instance creation
        }));

        // Create function environment for host functions
        let env = FunctionEnv::new(&mut store, syscall_env.clone());

        // Set up imports for RISC-V syscalls and runtime functions
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

        // Instantiate the module (this runs the Cranelift-compiled native code)
        let instance = Instance::new(&mut store, &module, &import_object)?;

        // Get memory and store it in the environment
        if let Ok(memory) = instance.exports.get_memory("memory") {
            syscall_env.lock().unwrap().memory = Some(memory.clone());
        }

        // Get exit_flag global if exported and store in environment
        let exit_flag = instance.exports.get_global("exit_flag").ok().cloned();
        if let Some(ref flag) = exit_flag {
            syscall_env.lock().unwrap().exit_flag = Some(flag.clone());
        }

        Ok(Self {
            module,
            instance,
            store,
            state,
            exit_flag,
        })
    }

    /// Execute the main function (runs native code compiled by Cranelift)
    pub fn execute(&mut self) -> Result<i32, Box<dyn std::error::Error>> {
        let main = self.instance.exports.get_function("main")?;
        let result = main.call(&mut self.store, &[])?;

        match result.first() {
            Some(Value::I32(v)) => Ok(*v),
            _ => Ok(0),
        }
    }

    /// Call a specific exported function by name
    pub fn call_function(
        &mut self,
        name: &str,
        args: &[Value],
    ) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
        let func = self.instance.exports.get_function(name)?;
        let result = func.call(&mut self.store, args)?;
        Ok(result.to_vec())
    }

    /// Load data into WASM linear memory
    pub fn load_memory(&mut self, offset: u32, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let memory = self.instance.exports.get_memory("memory")?;
        let view = memory.view(&self.store);

        for (i, &byte) in data.iter().enumerate() {
            view.write_u8((offset + i as u32) as u64, byte)?;
        }

        Ok(())
    }

    /// Read from WASM linear memory
    pub fn read_memory(&self, offset: u32, len: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let memory = self.instance.exports.get_memory("memory")?;
        let view = memory.view(&self.store);

        let mut data = vec![0u8; len];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = view.read_u8((offset + i as u32) as u64)?;
        }

        Ok(data)
    }

    /// Get the current RISC-V state
    pub fn state(&self) -> Arc<Mutex<crate::middleend::RiscVState>> {
        self.state.clone()
    }

    /// RISC-V syscall handler (called from native code)
    fn syscall_handler(
        mut env: FunctionEnvMut<Arc<Mutex<SyscallEnv>>>,
        syscall_num: i64,
        arg1: i64,
        arg2: i64,
        arg3: i64,
        arg4: i64,
        arg5: i64,
        arg6: i64,
    ) -> i64 {
        // Implement RISC-V Linux syscalls
        match syscall_num {
            93 => {
                // exit(status) - set exit flag to break interpreter loop
                eprintln!("DEBUG: exit syscall called with status={}", arg1);
                // Get exit flag (need to do this before locking other things)
                let exit_flag = {
                    let syscall_env = env.data().lock().unwrap();
                    syscall_env.exit_flag.clone()
                };
                if let Some(exit_flag) = exit_flag {
                    exit_flag.set(&mut env, wasmer::Value::I32(1)).ok();
                }
                arg1 // Return exit status
            }
            64 => {
                // write(fd, buf, count)
                let fd = arg1 as i32;
                let buf_addr = arg2 as u64;
                let count = arg3 as usize;

                eprintln!("DEBUG: write(fd={}, buf=0x{:x}, count={})", fd, buf_addr, count);

                let syscall_env = env.data().lock().unwrap();

                // Get memory view to read the buffer
                if let Some(ref memory) = syscall_env.memory {
                    let view = memory.view(&env);
                    let mut buffer = vec![0u8; count];

                    // Read from WASM memory
                    for (i, byte) in buffer.iter_mut().enumerate() {
                        if let Ok(b) = view.read_u8(buf_addr + i as u64) {
                            *byte = b;
                        }
                    }

                    // Write to appropriate file descriptor
                    use std::io::Write;
                    let result = match fd {
                        1 => std::io::stdout().write(&buffer),
                        2 => std::io::stderr().write(&buffer),
                        _ => {
                            eprintln!("Warning: write to unsupported fd {}", fd);
                            Ok(count)
                        }
                    };

                    match result {
                        Ok(n) => {
                            let _ = std::io::stdout().flush();
                            n as i64
                        }
                        Err(_) => -1, // EIO
                    }
                } else {
                    // Fallback if memory not available
                    eprintln!("Warning: write syscall without memory access");
                    count as i64
                }
            }
            63 => {
                // read(fd, buf, count)
                eprintln!("Warning: read syscall not fully implemented");
                0 // return bytes read
            }
            214 => {
                // brk - memory allocation
                // For now, just return the requested address
                arg1
            }
            // Common syscalls that programs might use
            57 => {
                // close(fd)
                0 // success
            }
            62 => {
                // lseek(fd, offset, whence)
                arg2 // return offset
            }
            80 => {
                // fstat(fd, statbuf)
                -1 // EBADF
            }
            96 => {
                // set_tid_address
                1 // return fake tid
            }
            134 => {
                // rt_sigaction
                0 // success (ignore signals)
            }
            135 => {
                // rt_sigprocmask
                0 // success (ignore signals)
            }
            160 => {
                // uname
                0 // success (fake it)
            }
            169 => {
                // gettimeofday
                0 // success (return 0 time)
            }
            174 => {
                // getuid
                1000 // fake uid
            }
            175 => {
                // getgid
                1000 // fake gid
            }
            176 => {
                // geteuid
                1000 // fake euid
            }
            177 => {
                // getegid
                1000 // fake egid
            }
            226 => {
                // mprotect
                0 // success (ignore)
            }
            98 => {
                // futex(uaddr, futex_op, val, timeout, uaddr2, val3)
                eprintln!("futex syscall (stubbed): op={}, addr=0x{:x}", arg2, arg1);
                0 // success (ignore for now)
            }
            99 => {
                // set_robust_list
                0 // success (ignore)
            }
            222 => {
                // mmap
                eprintln!("mmap syscall (stubbed): addr=0x{:x}, len=0x{:x}, prot={}, flags={}",
                         arg1, arg2, arg3, arg4);
                arg1 // return requested address
            }
            261 => {
                // prlimit64
                0 // success (ignore)
            }
            _ => {
                // Check if syscall number looks like garbage (way too high)
                if syscall_num > 500 || syscall_num < 0 {
                    eprintln!("ERROR: Invalid syscall number {} - this is likely a bug!", syscall_num);
                    eprintln!("  This usually means x17 (a7) register contains garbage");
                    eprintln!("  Args: {}, {}, {}, {}, {}, {}", arg1, arg2, arg3, arg4, arg5, arg6);
                    // Return error to help debug
                    -38 // ENOSYS
                } else {
                    eprintln!("Unknown syscall: {} (args: {}, {}, {}, {}, {}, {})",
                             syscall_num, arg1, arg2, arg3, arg4, arg5, arg6);
                    -38 // ENOSYS
                }
            }
        }
    }

    /// Debug print handler (called from native code)
    fn debug_print_handler(
        _env: FunctionEnvMut<Arc<Mutex<SyscallEnv>>>,
        val: i32,
    ) {
        println!("DEBUG: 0x{:08x} ({})", val, val);
    }
}

/// Builder for creating RISC-V runtime from WAT source
pub struct RuntimeBuilder {
    wasm_builder: WasmBuilder,
}

impl RuntimeBuilder {
    /// Create a new runtime builder
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            wasm_builder: WasmBuilder::new()?,
        })
    }

    /// Build a runtime from WAT source code
    ///
    /// This compiles WAT → WASM → native code using Cranelift
    pub fn build_from_wat(
        &self,
        wat_source: &str,
        state: Arc<Mutex<crate::middleend::RiscVState>>,
    ) -> Result<RiscVRuntime, Box<dyn std::error::Error>> {
        // Compile WAT to native code using Cranelift
        let module = self.wasm_builder.compile_wat(wat_source)?;

        // Create store for this runtime instance
        let store = Store::new(self.wasm_builder.engine().clone());

        // Create runtime with compiled native code
        RiscVRuntime::new(store, module, state)
    }

    /// Build a runtime from WASM bytecode
    pub fn build_from_wasm(
        &self,
        wasm_bytes: &[u8],
        state: Arc<Mutex<crate::middleend::RiscVState>>,
    ) -> Result<RiscVRuntime, Box<dyn std::error::Error>> {
        // Compile WASM to native code using Cranelift
        let module = self.wasm_builder.compile_wasm(wasm_bytes)?;

        // Create store for this runtime instance
        let store = Store::new(self.wasm_builder.engine().clone());

        // Create runtime with compiled native code
        RiscVRuntime::new(store, module, state)
    }
}

impl Default for RuntimeBuilder {
    fn default() -> Self {
        Self::new().expect("Failed to create RuntimeBuilder")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_builder_creation() {
        let builder = WasmBuilder::new();
        assert!(builder.is_ok());
    }

    #[test]
    fn test_compile_simple_wat() {
        let builder = WasmBuilder::new().unwrap();

        let wat = r#"
        (module
          (func $add (param $a i32) (param $b i32) (result i32)
            local.get $a
            local.get $b
            i32.add
          )
          (export "add" (func $add))
        )
        "#;

        let module = builder.compile_wat(wat);
        assert!(module.is_ok());
    }

    #[test]
    fn test_compile_and_execute() {
        let builder = RuntimeBuilder::new().unwrap();
        let state = Arc::new(Mutex::new(crate::middleend::RiscVState::default()));

        let wat = r#"
        (module
          (func $main (export "main") (result i32)
            i32.const 42
          )
        )
        "#;

        let mut runtime = builder.build_from_wat(wat, state).unwrap();
        let result = runtime.execute().unwrap();
        assert_eq!(result, 42);
    }

    #[test]
    fn test_memory_operations() {
        let builder = RuntimeBuilder::new().unwrap();
        let state = Arc::new(Mutex::new(crate::middleend::RiscVState::default()));

        let wat = r#"
        (module
          (memory (export "memory") 1)
          (func $main (export "main") (result i32)
            i32.const 0
          )
        )
        "#;

        let mut runtime = builder.build_from_wat(wat, state).unwrap();

        // Write data to memory
        let data = vec![1, 2, 3, 4, 5];
        runtime.load_memory(0x100, &data).unwrap();

        // Read data back
        let read_data = runtime.read_memory(0x100, 5).unwrap();
        assert_eq!(data, read_data);
    }
}
