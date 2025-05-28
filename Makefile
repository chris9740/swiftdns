.PHONY: package test release

package:
	cargo deb

test: package
	docker build -f Dockerfile.test -t swiftdns:test .
	docker run --rm swiftdns:test

release: test
	@echo "✓ Release package tested and ready!"
	@echo "Install with: sudo dpkg -i target/debian/swiftdns_*.deb"
