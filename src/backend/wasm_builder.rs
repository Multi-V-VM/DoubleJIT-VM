use wasmer::{
    imports, wat2wasm, Engine, Function, FunctionEnv, FunctionEnvMut, Instance, Module, Store,
    Value,
};
use wasmer::sys::EngineBuilder;
use wasmer_compiler_singlepass::Singlepass;
use wasmer_wasix::{WasiEnvBuilder, WasiFunctionEnv};
use std::sync::{Arc, Mutex};
use crate::codegen::optimizer::{WatOptimizer, OptLevel as WatOptLevel, OptStats};

/// Optimization level for WASM compilation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptLevel {
    /// No optimizations - fastest compilation
    None,
    /// Basic optimizations - balanced
    Speed,
    /// Maximum optimizations - best runtime performance
    SpeedAndSize,
}

impl OptLevel {
    /// Convert to WAT optimizer level
    fn to_wat_opt_level(self) -> WatOptLevel {
        match self {
            OptLevel::None => WatOptLevel::None,
            OptLevel::Speed => WatOptLevel::Moderate,
            OptLevel::SpeedAndSize => WatOptLevel::Aggressive,
        }
    }
}

/// Backend builder that compiles WAT to native code using Singlepass
///
/// Pipeline: WAT → WAT Optimization → WASM bytecode → Singlepass → native x86/ARM code → Wasmer runtime
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
    /// WAT optimization statistics (from last compilation)
    last_opt_stats: Option<OptStats>,
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

        Ok(Self {
            engine,
            store,
            opt_level,
            last_opt_stats: None,
        })
    }

    /// Get the current optimization level
    pub fn opt_level(&self) -> OptLevel {
        self.opt_level
    }

    /// Get WAT optimization statistics from last compilation
    pub fn last_optimization_stats(&self) -> Option<&OptStats> {
        self.last_opt_stats.as_ref()
    }

    /// Compile WAT (WebAssembly Text) to native code and create a Wasmer module
    ///
    /// This performs the full compilation pipeline:
    /// 1. Optimize WAT code (constant propagation, dead code elimination, etc.)
    /// 2. Parse optimized WAT to WASM bytecode
    /// 3. Singlepass compiles WASM to native machine code (x86-64/ARM)
    /// 4. Returns a compiled Module ready for instantiation
    pub fn compile_wat(&mut self, wat_source: &str) -> Result<Module, Box<dyn std::error::Error>> {
        // Step 1: Optimize WAT code before compilation
        let wat_opt_level = self.opt_level.to_wat_opt_level();
        let optimized_wat = if wat_opt_level != WatOptLevel::None {
            let mut optimizer = WatOptimizer::new(wat_opt_level);
            let optimized = optimizer.optimize(wat_source);

            // Store optimization statistics
            self.last_opt_stats = Some(optimizer.stats().clone());

            optimized
        } else {
            self.last_opt_stats = None;
            wat_source.to_string()
        };

        // Step 2: Convert optimized WAT to WASM bytecode
        let wasm_bytes = wat2wasm(optimized_wat.as_bytes())?;

        // Step 3: Compile WASM to native code using Singlepass
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
    /// Program break (heap end) for brk syscall
    program_break: Arc<Mutex<u64>>,
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
        // Initialize program break at 0x100000 (1MB) - above .bss section
        let syscall_env = Arc::new(Mutex::new(SyscallEnv {
            state: state.clone(),
            memory: None, // Will be set after instance creation
            set_exit_flag_func: None, // Will be set after instance creation
            wasi_env: None, // Will be set after WASI initialization
            program_break: Arc::new(Mutex::new(0x100000)), // Start heap at 1MB
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
            },
            // Provide stub WASI functions to avoid needing full WASI initialization
            // This prevents TLS conflicts with binaries that manage their own TLS
            "wasi_snapshot_preview1" => {
                // Minimal fd_write that reads a single ciovec from memory and writes to stdout/err
                // Signature: fd_write(fd: i32, iovs: i32, iovs_len: i32, nwritten: i32) -> i32
                "fd_write" => Function::new_typed_with_env(
                    &mut store,
                    &env,
                    |env: FunctionEnvMut<Arc<Mutex<SyscallEnv>>>, fd: i32, iovs: i32, iovs_len: i32, nwritten: i32| -> i32 {
                        let memory_opt = {
                            let syscall_env = env.data().lock().unwrap();
                            syscall_env.memory.clone()
                        };

                        if let Some(memory) = memory_opt {
                            let view = memory.view(&env);

                            // Only support iovs_len >= 1 (we'll aggregate the first one; simple programs use 1)
                            if iovs_len <= 0 {
                                // Set nwritten to 0
                                let _ = view.write(nwritten as u64, &0u32.to_le_bytes());
                                return 0;
                            }

                            // ciovec layout on wasm32: [ptr: u32][len: u32]
                            let mut tmp = [0u8; 4];
                            if view.read(iovs as u64, &mut tmp).is_err() {
                                let _ = view.write(nwritten as u64, &0u32.to_le_bytes());
                                return 0;
                            }
                            let buf_ptr = u32::from_le_bytes(tmp) as u64;
                            if view.read(iovs as u64 + 4, &mut tmp).is_err() {
                                let _ = view.write(nwritten as u64, &0u32.to_le_bytes());
                                return 0;
                            }
                            let buf_len = u32::from_le_bytes(tmp) as usize;

                            // Read buffer
                            let mut buffer = vec![0u8; buf_len];
                            for i in 0..buf_len {
                                if let Ok(b) = view.read_u8(buf_ptr + i as u64) {
                                    buffer[i] = b;
                                } else {
                                    break;
                                }
                            }

                            // Write to host stdout/stderr
                            use std::io::Write;
                            eprintln!("DEBUG: WASI fd_write(fd={}, len={})", fd, buffer.len());
                            let write_res = match fd {
                                1 => {
                                    let res = std::io::stdout().write(&buffer);
                                    let _ = std::io::stdout().flush();
                                    res
                                }
                                2 => {
                                    let res = std::io::stderr().write(&buffer);
                                    let _ = std::io::stderr().flush();
                                    res
                                }
                                _ => Ok(buffer.len()),
                            };

                            let bytes_written = write_res.unwrap_or(0) as u32;
                            let _ = view.write(nwritten as u64, &bytes_written.to_le_bytes());
                            0 // success
                        } else {
                            // No memory bound; report 0 bytes written
                            0
                        }
                    }
                ),
                // Minimal fd_read that returns EOF by setting nread=0
                // Signature: fd_read(fd: i32, iovs: i32, iovs_len: i32, nread: i32) -> i32
                "fd_read" => Function::new_typed_with_env(
                    &mut store,
                    &env,
                    |env: FunctionEnvMut<Arc<Mutex<SyscallEnv>>>, _fd: i32, _iovs: i32, _iovs_len: i32, nread: i32| -> i32 {
                        if let Some(memory) = env.data().lock().unwrap().memory.clone() {
                            let view = memory.view(&env);
                            let _ = view.write(nread as u64, &0u32.to_le_bytes());
                        }
                        0 // success (EOF)
                    }
                ),
                "proc_exit" => Function::new_typed_with_env(
                    &mut store,
                    &env,
                    |mut env: FunctionEnvMut<Arc<Mutex<SyscallEnv>>>, code: i32| {
                        // Properly handle exit - set the exit flag
                        let set_exit_flag_func = {
                            let syscall_env = env.data().lock().unwrap();
                            syscall_env.set_exit_flag_func.clone()
                        };

                        if let Some(func) = set_exit_flag_func {
                            let _ = func.call(&mut env, &[Value::I32(1)]);
                        }

                        // Exit by terminating with a runtime error
                        // This properly stops execution
                        eprintln!("DEBUG: proc_exit called with code {}", code);
                        panic!("WASI proc_exit called with code: {}", code);
                    }
                ),
            }
        };

        // IMPORTANT: Do NOT use WASI at all!
        // WASI has its own TLS (thread-local storage) initialization that conflicts
        // with binaries compiled with libc (like add_test) that manage their own TLS
        // via set_tid_address and arch_prctl syscalls.
        //
        // We only use our custom syscall imports which properly stub TLS syscalls
        // without setting up conflicting TLS state.
        let import_object = custom_imports;

        // Instantiate the module with only custom imports (no WASI)
        let instance = Instance::new(&mut store, &module, &import_object)?;

        // Get memory and store it in the environment
        if let Ok(memory) = instance.exports.get_memory("memory") {
            syscall_env.lock().unwrap().memory = Some(memory.clone());
        }

        // Get set_exit_flag function if exported and store in environment
        let set_exit_flag_func = instance.exports.get_function("set_exit_flag").ok().cloned();
        if let Some(ref func) = set_exit_flag_func {
            syscall_env.lock().unwrap().set_exit_flag_func = Some(func.clone());
        }

        // WASI environment not stored - we skip WASI init to avoid TLS conflicts
        // if wasi_initialized {
        //     syscall_env.lock().unwrap().wasi_env = Some(Arc::new(Mutex::new(wasi_fn_env)));
        // }

        Ok(Self {
            module,
            instance,
            store,
            state,
            set_exit_flag_func,
        })
    }

    /// Initialize WASM register globals from RiscVState
    pub fn init_registers(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let set_reg = self.instance.exports.get_function("set_reg")?;

        // Copy all registers from RiscVState to WASM globals
        let reg_values: Vec<i64> = {
            let state = self.state.lock().unwrap();
            state.x_regs.to_vec()
        };

        for (i, &val) in reg_values.iter().enumerate() {
            if val != 0 {  // Only set non-zero registers for efficiency
                set_reg.call(&mut self.store, &[Value::I32(i as i32), Value::I64(val)])?;
                eprintln!("DEBUG: Initialized register x{} = 0x{:x}", i, val);
            }
        }

        Ok(())
    }

    /// Execute the main function (runs native code compiled by Cranelift)
    pub fn execute(&mut self) -> Result<i32, Box<dyn std::error::Error>> {
        // Initialize registers from state BEFORE executing
        self.init_registers()?;

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
        // Debug: log every syscall with hex addresses for easier debugging
        eprintln!("SYSCALL: num={} (0x{:x}), args=(0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x})",
                 syscall_num, syscall_num as u64, arg1 as u64, arg2 as u64, arg3 as u64, arg4 as u64, arg5 as u64, arg6 as u64);

        // Implement RISC-V Linux syscalls
        let result = match syscall_num {
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
            66 => {
                // writev(fd, iov, iovcnt)
                let fd = arg1 as i32;
                let iov_addr = arg2 as u64;
                let iovcnt = arg3 as usize;

                let memory_opt = {
                    let syscall_env = env.data().lock().unwrap();
                    syscall_env.memory.clone()
                };

                if let Some(memory) = memory_opt {
                    let view = memory.view(&env);
                    use std::io::Write;

                    let mut total_written: usize = 0;
                    for i in 0..iovcnt {
                        let base_ptr_off = iov_addr + (i as u64) * 16;
                        let len_off = base_ptr_off + 8;

                        let mut tmp = [0u8; 8];
                        if view.read(base_ptr_off, &mut tmp).is_err() { break; }
                        let base_ptr = u64::from_le_bytes(tmp);
                        if view.read(len_off, &mut tmp).is_err() { break; }
                        let len = u64::from_le_bytes(tmp) as usize;

                        if len == 0 { continue; }
                        let mut buffer = vec![0u8; len];
                        for j in 0..len { if let Ok(b) = view.read_u8(base_ptr + j as u64) { buffer[j] = b; } else { break; } }

                        let res = match fd { 1 => std::io::stdout().write(&buffer), 2 => std::io::stderr().write(&buffer), _ => Ok(len) };
                        match res { Ok(n) => { total_written += n; }, Err(_) => {} }
                    }

                    // Flush
                    let _ = std::io::stdout().flush();
                    let _ = std::io::stderr().flush();
                    total_written as i64
                } else {
                    0
                }
            }
            63 => {
                // read(fd, buf, count)
                eprintln!("Warning: read syscall not fully implemented");
                0 // return bytes read
            }
            214 => {
                // brk - memory allocation/deallocation
                // brk(0) returns current program break
                // brk(addr) sets new program break and returns it on success
                let program_break_arc = env.data().lock().unwrap().program_break.clone();
                let mut current_break = program_break_arc.lock().unwrap();

                if arg1 == 0 {
                    // brk(0) - return current program break
                    eprintln!("DEBUG: brk(0) returning current break: 0x{:x}", *current_break);
                    *current_break as i64
                } else {
                    // brk(addr) - set new program break
                    let new_break = arg1 as u64;
                    eprintln!("DEBUG: brk(0x{:x}) - setting new break (was 0x{:x})", new_break, *current_break);

                    // TODO: Check if new_break is within reasonable bounds
                    // For now, just accept it
                    *current_break = new_break;
                    new_break as i64
                }
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
                let fd = arg1 as i32;
                let stat_addr = arg2 as u64;
                eprintln!("DEBUG: fstat(fd={}, stat=0x{:x})", fd, stat_addr);

                let memory = env.data().lock().unwrap().memory.clone();
                if let Some(memory) = memory {
                    let view = memory.view(&env);

                    // Minimal struct stat for riscv64 (subset):
                    // offset 16: st_mode (u32)
                    // offset 24: st_uid  (u32)
                    // offset 28: st_gid  (u32)
                    // offset 48: st_blksize (u64)
                    // others left zero

                    let mode: u32 = if fd == 0 || fd == 1 || fd == 2 {
                        // Character device with 0666 perms
                        0o020666
                    } else {
                        // Regular file with 0666 perms
                        0o100666
                    };

                    // Zero a reasonable prefix to avoid stale reads (0..=128)
                    let zero = [0u8; 128];
                    let _ = view.write(stat_addr, &zero);

                    // Write fields
                    let _ = view.write(stat_addr + 16, &mode.to_le_bytes());
                    let _ = view.write(stat_addr + 24, &(1000u32).to_le_bytes()); // uid
                    let _ = view.write(stat_addr + 28, &(1000u32).to_le_bytes()); // gid
                    let _ = view.write(stat_addr + 48, &(4096u64).to_le_bytes()); // blksize

                    0 // success
                } else {
                    -1 // EFAULT
                }
            }
            // Note: syscalls 96, 134, 135, 160 are implemented later with proper TLS handling
            169 => {
                // gettimeofday(tv, tz)
                let tv_addr = arg1 as u64;
                let memory = env.data().lock().unwrap().memory.clone();
                if let Some(memory) = memory { 
                    let view = memory.view(&env);
                    // Provide a monotonic-ish fake time
                    let secs: u64 = 1700000000;
                    let usec: u64 = 0;
                    let _ = view.write(tv_addr, &secs.to_le_bytes());
                    let _ = view.write(tv_addr + 8, &usec.to_le_bytes());
                    0
                } else { -1 }
            }
            113 | 403 => {
                // clock_gettime(clockid, timespec*)
                let ts_addr = arg2 as u64;
                let memory = env.data().lock().unwrap().memory.clone();
                if let Some(memory) = memory {
                    let view = memory.view(&env);
                    let secs: u64 = 1700000000;
                    let nsec: u64 = 0;
                    let _ = view.write(ts_addr, &secs.to_le_bytes());
                    let _ = view.write(ts_addr + 8, &nsec.to_le_bytes());
                    0
                } else { -1 }
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
            94 => {
                // exit_group(status) - terminate all threads in process
                eprintln!("DEBUG: exit_group syscall called with status={}", arg1);
                // Set exit flag like regular exit
                let set_exit_flag_func = {
                    let syscall_env = env.data().lock().unwrap();
                    syscall_env.set_exit_flag_func.clone()
                };
                if let Some(func) = set_exit_flag_func {
                    func.call(&mut env, &[wasmer::Value::I32(1)]).ok();
                }
                arg1 // Return exit status
            }
            131 => {
                // sigaltstack(ss, old_ss) - set/get signal stack
                eprintln!("DEBUG: sigaltstack syscall (stubbed)");
                0 // success (stub - we don't use signal stacks)
            }
            172 => {
                // getpid() - get process ID
                // Return a fixed PID for now
                eprintln!("DEBUG: getpid syscall");
                1000 // Return fixed PID
            }
            178 => {
                // gettid() - get thread ID
                // Return a fixed TID for now
                eprintln!("DEBUG: gettid syscall");
                1000 // Return fixed TID (same as PID for single-threaded)
            }
            // getrandom - different numbers on some archs
            318 | 278 => {
                // getrandom(buf, buflen, flags)
                // Critical for libc initialization (stack canaries, ASLR)
                let buf_addr = arg1 as u64;
                let buf_len = arg2 as usize;
                eprintln!("DEBUG: getrandom syscall: buf=0x{:x}, len={}", buf_addr, buf_len);

                let memory = env.data().lock().unwrap().memory.clone();

                if let Some(memory) = memory {
                    let view = memory.view(&env);

                    // Fill buffer with random data (or zeros if getrandom not available)
                    for i in 0..buf_len {
                        // Use a simple pseudo-random value based on index
                        // In production, this should use actual random data
                        let random_byte = ((i * 17 + 42) % 256) as u8;
                        view.write_u8(buf_addr + i as u64, random_byte).ok();
                    }
                    buf_len as i64 // Return number of bytes written
                } else {
                    eprintln!("ERROR: No memory for getrandom");
                    -1 // EFAULT
                }
            }
            158 => {
                // arch_prctl(code, addr) - x86-64 specific TLS setup
                // code=0x1002 (ARCH_SET_FS), code=0x1003 (ARCH_GET_FS)
                eprintln!("DEBUG: arch_prctl syscall: code=0x{:x}, addr=0x{:x}", arg1, arg2);
                0 // Success (stub - WASM doesn't need TLS setup)
            }
            // rseq - different numbers on some archs
            334 | 293 => {
                // rseq(rseq, rseq_len, flags, sig) - restartable sequences
                eprintln!("DEBUG: rseq syscall (stubbed)");
                0 // Success (stub - not needed in WASM)
            }
            89 => {
                // readlink(path, buf, bufsiz)
                eprintln!("DEBUG: readlink syscall: path=0x{:x}, buf=0x{:x}, size={}", arg1, arg2, arg3);
                -2 // ENOENT (file not found - we don't have a filesystem)
            }
            21 => {
                // access(pathname, mode)
                eprintln!("DEBUG: access syscall: path=0x{:x}, mode={}", arg1, arg2);
                -2 // ENOENT (file not found)
            }
            17 => {
                // getcwd(buf, size)
                let buf_addr = arg1 as u64;
                eprintln!("DEBUG: getcwd syscall: buf=0x{:x}, size={}", buf_addr, arg2);

                let memory = env.data().lock().unwrap().memory.clone();

                if let Some(memory) = memory {
                    let view = memory.view(&env);
                    let cwd = b"/\0"; // Return root directory

                    // Write current directory to buffer
                    for (i, &byte) in cwd.iter().enumerate() {
                        view.write_u8(buf_addr + i as u64, byte).ok();
                    }
                    arg1 // Return buffer address on success
                } else {
                    -1 // EFAULT
                }
            }
            179 => {
                // sysinfo(info)
                eprintln!("DEBUG: sysinfo syscall (stubbed)");
                0 // Success (stub - return fake system info)
            }
            135 => {
                // rt_sigprocmask(how, set, oldset, sigsetsize)
                // Signal mask manipulation - critical for libc
                // eprintln!("DEBUG: rt_sigprocmask syscall: how={}, set=0x{:x}, oldset=0x{:x}, size={}",
                //     arg1, arg2, arg3, arg4);

                // For now, stub this - just succeed without changing anything
                // In a full implementation, we'd need to track signal masks
                // but for JIT execution, signals are handled by the host OS
                0 // Success
            }
            134 => {
                // rt_sigaction(signum, act, oldact, sigsetsize)
                // Signal handler registration
                eprintln!("DEBUG: rt_sigaction syscall: sig={}, act=0x{:x}, oldact=0x{:x}",
                    arg1, arg2, arg3);
                0 // Success (stub)
            }
            13 => {
                // rt_sigreturn() - return from signal handler
                eprintln!("DEBUG: rt_sigreturn syscall (stubbed)");
                0
            }
            // Note: syscall 99 (set_robust_list) already defined above
            96 => {
                // set_tid_address(tidptr)
                eprintln!("DEBUG: set_tid_address syscall: tidptr=0x{:x}", arg1);
                1000 // Return fake TID
            }
            160 => {
                // uname(buf) - system information
                eprintln!("DEBUG: uname syscall: buf=0x{:x}", arg1);

                let memory = env.data().lock().unwrap().memory.clone();

                if let Some(memory) = memory {
                    let view = memory.view(&env);
                    let buf_addr = arg1 as u64;

                    // Fill in minimal utsname structure (6 strings of 65 bytes each)
                    let sysname = b"Linux\0";
                    let nodename = b"doublejit\0";
                    let release = b"5.15.0\0";
                    let version = b"#1 SMP\0";
                    let machine = b"riscv64\0";

                    // Write sysname at offset 0
                    for (i, &byte) in sysname.iter().enumerate() {
                        view.write_u8(buf_addr + i as u64, byte).ok();
                    }

                    // Write nodename at offset 65
                    for (i, &byte) in nodename.iter().enumerate() {
                        view.write_u8(buf_addr + 65 + i as u64, byte).ok();
                    }

                    // Write release at offset 130
                    for (i, &byte) in release.iter().enumerate() {
                        view.write_u8(buf_addr + 130 + i as u64, byte).ok();
                    }

                    // Write version at offset 195
                    for (i, &byte) in version.iter().enumerate() {
                        view.write_u8(buf_addr + 195 + i as u64, byte).ok();
                    }

                    // Write machine at offset 260
                    for (i, &byte) in machine.iter().enumerate() {
                        view.write_u8(buf_addr + 260 + i as u64, byte).ok();
                    }

                    0 // Success
                } else {
                    -1 // EFAULT
                }
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
                    eprintln!("⚠️  UNKNOWN SYSCALL {}: args=({}, {}, {}, {}, {}, {}) - returning ENOSYS",
                             syscall_num, arg1, arg2, arg3, arg4, arg5, arg6);
                    -38 // ENOSYS
                }
            }
        };

        // Log the result of the syscall
        if result < 0 {
            eprintln!("  → returned ERROR: {} ({})", result, if result == -38 { "ENOSYS" } else if result == -1 { "EFAULT" } else if result == -2 { "ENOENT" } else { "?" });
        } else {
            eprintln!("  → returned: {}", result);
        }

        result
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

    /// Create a new runtime builder with a specific optimization level
    pub fn with_opt_level(opt_level: OptLevel) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            wasm_builder: WasmBuilder::with_opt_level(opt_level)?,
        })
    }

    /// Get optimization statistics from last compilation
    pub fn last_optimization_stats(&self) -> Option<&OptStats> {
        self.wasm_builder.last_optimization_stats()
    }

    /// Build a runtime from WAT source code
    ///
    /// This compiles WAT → WAT Optimization → WASM → native code using Singlepass
    pub fn build_from_wat(
        &mut self,
        wat_source: &str,
        state: Arc<Mutex<crate::middleend::RiscVState>>,
    ) -> Result<RiscVRuntime, Box<dyn std::error::Error>> {
        // Compile WAT to native code (includes WAT optimization)
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
