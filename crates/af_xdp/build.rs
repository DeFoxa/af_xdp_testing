fn main() {
    println!("cargo:rustc-link-lib=bpf");
    println!("cargo:rustc-link-search=/lib/x86_64-linux-gnu");
}
