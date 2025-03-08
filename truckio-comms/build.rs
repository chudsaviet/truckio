use glob::glob;
use micropb_gen::{Config, Generator};
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

    let mut pbgen = Generator::new();
    pbgen
        .use_container_heapless()
        .add_protoc_arg("-Iprotos")
        .configure(
            ".truckio.comms.RadioPacket.payload",
            Config::new().max_bytes(64),
        )
        .configure(
            ".truckio.comms.RadioPacket.nonce",
            Config::new().max_bytes(12),
        )
        .configure(
            ".truckio.comms.command.Command.nonce",
            Config::new().max_bytes(12),
        )
        .compile_protos(
            &protos,
            std::env::var("OUT_DIR").unwrap() + "/protos_generated.rs",
        )
        .unwrap();

    println!("cargo:rerun-if-changed=proto");
}

fn main() {
    protos_generate();
}
