use wasmer::{
    imports, wat2wasm, Engine, Function, FunctionEnv, FunctionEnvMut, Instance, Module, Store,
    Value,
};
use wasmer_compiler_cranelift::Cranelift;
use std::sync::{Arc, Mutex};

/// Backend builder that compiles WAT to native code using Cranelift
///
/// Pipeline: WAT → WASM bytecode → Cranelift IR → native x86/ARM code → Wasmer runtime
pub struct WasmBuilder {
    /// Cranelift compiler engine
    engine: Engine,
    /// Wasmer store for managing compiled modules
    store: Store,
}

impl WasmBuilder {
    /// Create a new WasmBuilder with Cranelift compiler
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Configure Cranelift compiler
        let compiler = Cranelift::default();

        // Create engine with Cranelift backend
        // This will compile WASM to native code (x86-64, ARM, etc.)
        let engine = Engine::from(compiler);

        // Create store with the Cranelift engine
        let store = Store::new(engine.clone());

        Ok(Self { engine, store })
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
}

impl RiscVRuntime {
    /// Create a new runtime from a compiled module
    pub fn new(
        mut store: Store,
        module: Module,
        state: Arc<Mutex<crate::middleend::RiscVState>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Create function environment for host functions
        let env = FunctionEnv::new(&mut store, state.clone());

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

        Ok(Self {
            module,
            instance,
            store,
            state,
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
        mut env: FunctionEnvMut<Arc<Mutex<crate::middleend::RiscVState>>>,
        syscall_num: i64,
        arg1: i64,
        arg2: i64,
        arg3: i64,
        arg4: i64,
        arg5: i64,
        arg6: i64,
    ) -> i64 {
        let _state = env.data().lock().unwrap();

        // Implement RISC-V Linux syscalls
        match syscall_num {
            93 => {
                // exit
                println!("RISC-V exit({})", arg1);
                std::process::exit(arg1 as i32);
            }
            64 => {
                // write(fd, buf, count)
                println!("RISC-V write(fd={}, buf=0x{:x}, count={})", arg1, arg2, arg3);
                // TODO: Implement actual write to stdout/stderr
                arg3 as i64 // return bytes written
            }
            63 => {
                // read(fd, buf, count)
                println!("RISC-V read(fd={}, buf=0x{:x}, count={})", arg1, arg2, arg3);
                // TODO: Implement actual read
                0 // return bytes read
            }
            214 => {
                // brk - memory allocation
                println!("RISC-V brk(0x{:x})", arg1);
                arg1 // return requested address
            }
            _ => {
                println!("Unknown syscall: {}", syscall_num);
                -1 // ENOSYS
            }
        }
    }

    /// Debug print handler (called from native code)
    fn debug_print_handler(
        _env: FunctionEnvMut<Arc<Mutex<crate::middleend::RiscVState>>>,
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
