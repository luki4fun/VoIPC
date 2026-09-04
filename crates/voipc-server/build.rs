// The web client bundle (client/dist-web) is embedded into the server binary.
// rust-embed refuses to compile when the folder is missing, so make sure it
// exists (empty until ./build-web.sh runs) and rebuild whenever it changes.
fn main() {
    std::fs::create_dir_all("../../client/dist-web").expect("create client/dist-web");
    println!("cargo:rerun-if-changed=../../client/dist-web");
}
