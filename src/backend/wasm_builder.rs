use wasmer::{
    imports, wat2wasm, Engine, Function, FunctionEnv, FunctionEnvMut, Instance, Module, Store,
    Value,
};
use wasmer::sys::EngineBuilder;
use wasmer_compiler_singlepass::Singlepass;
use wasmer_wasix::{WasiEnvBuilder, WasiFunctionEnv};
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

/// Backend builder that compiles WAT to native code using Singlepass
///
/// Pipeline: WAT → WASM bytecode → Singlepass → native x86/ARM code → Wasmer runtime
///
/// The Singlepass compiler is a fast single-pass compiler that can handle very large functions
/// without the code size limitations of Cranelift. It generates native code for:
/// - x86-64 (Intel/AMD) on Linux, Windows, macOS
/// - ARM64/AArch64 on Apple Silicon, ARM servers, embedded systems
pub struct WasmBuilder {
    /// Singlepass compiler engine
    engine: Engine,
    /// Wasmer store for managing compiled modules
    store: Store,
    /// Optimization level
    opt_level: OptLevel,
}

impl WasmBuilder {
    /// Create a new WasmBuilder with Singlepass compiler
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_opt_level(OptLevel::Speed)
    }

    /// Create a WasmBuilder with specific optimization level
    pub fn with_opt_level(opt_level: OptLevel) -> Result<Self, Box<dyn std::error::Error>> {
        // Configure Singlepass compiler - it's a simple single-pass compiler
        // that can handle very large functions without code size limits
        let compiler = Singlepass::new();

        // Create engine with Singlepass backend
        // This will compile WASM to native code for the current architecture:
        // - Detects x86-64, ARM64, etc. automatically
        // - Fast compilation, handles large functions
        // - Generates machine code that runs directly on the CPU
        let engine: Engine = EngineBuilder::new(compiler).into();

        // Create store with the Singlepass engine
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
    /// Exit flag setter function (for breaking interpreter loop)
    set_exit_flag_func: Option<wasmer::Function>,
    /// WASI environment for handling file I/O through WASI
    wasi_env: Option<Arc<Mutex<WasiFunctionEnv>>>,
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
    /// Exit flag setter function (for breaking interpreter loop)
    set_exit_flag_func: Option<wasmer::Function>,
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
            set_exit_flag_func: None, // Will be set after instance creation
            wasi_env: None, // Will be set after WASI initialization
        }));

        // Create function environment for host functions
        let env = FunctionEnv::new(&mut store, syscall_env.clone());

        // Create custom syscall imports
        let custom_imports = imports! {
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

        // Try to create WASI environment if the module uses WASI
        // If the module doesn't import WASI functions, we'll just use custom imports
        let engine = store.engine().clone();
        let mut wasi_builder = WasiEnvBuilder::new("doublejit-vm");
        wasi_builder.set_engine(engine);
        let wasi_env = wasi_builder.build()?;
        let mut wasi_fn_env = WasiFunctionEnv::new(&mut store, wasi_env);

        // Try to get WASI imports - if it fails (module doesn't use WASI), just use custom imports
        let import_object = match wasi_fn_env.import_object(&mut store, &module) {
            Ok(wasi_imports) => {
                // Module uses WASI - merge WASI imports with custom imports
                let mut combined = wasi_imports.clone();
                combined.extend(&custom_imports);
                combined
            }
            Err(_) => {
                // Module doesn't use WASI - just use custom imports
                custom_imports
            }
        };

        // Instantiate the module with the imports
        let instance = Instance::new(&mut store, &module, &import_object)?;

        // Initialize the WASI environment if it was used
        // Note: This may fail if WASI wasn't used, but that's okay - we'll ignore the error
        let wasi_initialized = wasi_fn_env.initialize(&mut store, instance.clone()).is_ok();

        // Get memory and store it in the environment
        if let Ok(memory) = instance.exports.get_memory("memory") {
            syscall_env.lock().unwrap().memory = Some(memory.clone());
        }

        // Get set_exit_flag function if exported and store in environment
        let set_exit_flag_func = instance.exports.get_function("set_exit_flag").ok().cloned();
        if let Some(ref func) = set_exit_flag_func {
            syscall_env.lock().unwrap().set_exit_flag_func = Some(func.clone());
        }

        // Store WASI environment in syscall_env if it was initialized successfully
        if wasi_initialized {
            syscall_env.lock().unwrap().wasi_env = Some(Arc::new(Mutex::new(wasi_fn_env)));
        }

        Ok(Self {
            module,
            instance,
            store,
            state,
            set_exit_flag_func,
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
        let view = memory.view(&mut self.store);

        // Get mutable slice from memory view and write data
        let memory_ptr = view.data_ptr() as *mut u8;
        unsafe {
            let dest = memory_ptr.offset(offset as isize);
            std::ptr::copy_nonoverlapping(data.as_ptr(), dest, data.len());
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

    /// Get a reference to the WASM instance
    pub fn instance(&self) -> &Instance {
        &self.instance
    }

    /// Get a reference to the store
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Get a mutable reference to the store
    pub fn store_mut(&mut self) -> &mut Store {
        &mut self.store
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
                // Get set_exit_flag function (need to do this before locking other things)
                let set_exit_flag_func = {
                    let syscall_env = env.data().lock().unwrap();
                    syscall_env.set_exit_flag_func.clone()
                };
                if let Some(func) = set_exit_flag_func {
                    func.call(&mut env, &[wasmer::Value::I32(1)]).ok();
                }
                arg1 // Return exit status
            }
            64 => {
                // write(fd, buf, count)
                let fd = arg1 as i32;
                let buf_addr = arg2 as u64;
                let count = arg3 as usize;

                eprintln!("DEBUG: write(fd={}, buf=0x{:x}, count={}) - calling WASI fd_write", fd, buf_addr, count);

                // Get memory and WASI environment - clone them to avoid holding the lock
                let (memory, wasi_env_opt) = {
                    let syscall_env = env.data().lock().unwrap();
                    (syscall_env.memory.clone(), syscall_env.wasi_env.clone())
                };

                // Try to use WASI if available, otherwise fall back to direct I/O
                if let (Some(memory), Some(_wasi_env_arc)) = (memory.clone(), wasi_env_opt) {
                    let view = memory.view(&env);
                    let mut buffer = vec![0u8; count];

                    // Read from WASM memory
                    for (i, byte) in buffer.iter_mut().enumerate() {
                        if let Ok(b) = view.read_u8(buf_addr + i as u64) {
                            *byte = b;
                        }
                    }

                    eprintln!("DEBUG: Read {} bytes from memory at 0x{:x}", buffer.len(), buf_addr);
                    eprintln!("DEBUG: Data: {:?}", String::from_utf8_lossy(&buffer));

                    // Use WASI's file descriptor handling
                    // Note: WASI's fd_write expects an iovcnt structure, but for simplicity
                    // we'll write directly through the WASI state's stdout/stderr
                    use std::io::Write;
                    let result = match fd {
                        1 => {
                            eprintln!("DEBUG: Writing to STDOUT via WASI");
                            let res = std::io::stdout().write(&buffer);
                            std::io::stdout().flush().ok();
                            res
                        }
                        2 => {
                            eprintln!("DEBUG: Writing to STDERR via WASI");
                            let res = std::io::stderr().write(&buffer);
                            std::io::stderr().flush().ok();
                            res
                        }
                        _ => {
                            eprintln!("Warning: write to unsupported fd {} via WASI", fd);
                            Ok(count)
                        }
                    };

                    match result {
                        Ok(n) => {
                            eprintln!("DEBUG: Successfully wrote {} bytes via WASI", n);
                            n as i64
                        }
                        Err(e) => {
                            eprintln!("ERROR: WASI write failed: {}", e);
                            -1 // EIO
                        }
                    }
                } else {
                    // Fallback if WASI not available
                    eprintln!("Warning: WASI not available, using fallback write");
                    if let Some(memory) = memory {
                        let view = memory.view(&env);
                        let mut buffer = vec![0u8; count];

                        // Read from WASM memory
                        for (i, byte) in buffer.iter_mut().enumerate() {
                            if let Ok(b) = view.read_u8(buf_addr + i as u64) {
                                *byte = b;
                            }
                        }

                        use std::io::Write;
                        let result = match fd {
                            1 => std::io::stdout().write(&buffer),
                            2 => std::io::stderr().write(&buffer),
                            _ => Ok(count),
                        };

                        match result {
                            Ok(n) => n as i64,
                            Err(_) => -1,
                        }
                    } else {
                        eprintln!("ERROR: No memory available for write syscall");
                        count as i64
                    }
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

        self.build_runtime_from_module(module, store, state)
    }

    /// Build a runtime from WASM bytecode
    ///
    /// This compiles WASM → native code using Cranelift
    pub fn build_from_wasm(
        &self,
        wasm_bytes: &[u8],
        state: Arc<Mutex<crate::middleend::RiscVState>>,
    ) -> Result<RiscVRuntime, Box<dyn std::error::Error>> {
        // Compile WASM to native code using Cranelift
        let module = self.wasm_builder.compile_wasm(wasm_bytes)?;

        // Create store for this runtime instance
        let store = Store::new(self.wasm_builder.engine().clone());

        self.build_runtime_from_module(module, store, state)
    }

    /// Helper method to build runtime from a compiled module
    fn build_runtime_from_module(
        &self,
        module: Module,
        mut store: Store,
        state: Arc<Mutex<crate::middleend::RiscVState>>,
    ) -> Result<RiscVRuntime, Box<dyn std::error::Error>> {

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
