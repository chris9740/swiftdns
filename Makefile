build:
	cross build --release --target x86_64-unknown-linux-gnu

package:
	cargo deb

release: build package
