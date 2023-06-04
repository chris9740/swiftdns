build:
	cross build --release --target x86_64-unknown-linux-gnu

deb:
	cargo deb --no-build --target x86_64-unknown-linux-gnu

release: build deb
