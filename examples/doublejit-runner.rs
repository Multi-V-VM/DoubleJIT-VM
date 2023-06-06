use doublejit_vm::frontend::binary::Binary;

fn main(){
    let path = std::env::args().nth(1).expect("no path given");
    let bin =  Binary::parse(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        path
    )))
    .unwrap();
    // middle end, invoke native and have lock to prevent execution
    
}