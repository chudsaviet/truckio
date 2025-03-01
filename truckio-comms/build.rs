use glob::glob;
use micropb_gen;
// Because of micropb limitations, we have to build all protos into a singe .rs file.
fn protos_generate() {
    let paths_glob = glob("protos/*.proto").expect("Failed to read glob pattern.");
    let protos: Vec<String> = paths_glob
        .map(|p| {
            p.unwrap()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string()
        })
        .collect::<Vec<String>>();

    let mut gen = micropb_gen::Generator::new();
    gen.use_container_heapless()
        .add_protoc_arg("-Iprotos")
        .compile_protos(&protos, std::env::var("OUT_DIR").unwrap() + "/protos_generated.rs")
        .unwrap();

    println!("cargo:rerun-if-changed=proto");
}

fn main() {
    protos_generate();
}
