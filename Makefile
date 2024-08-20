.Phoney: main workspace
test_xdp_binary: 
	sudo RUST_LOG=info ./target/release/test_xdp_binary

af_xdp: 
	sudo RUST_LOG=info ./target/release/af_xdp

