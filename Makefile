# ssi/Makefile

.PHONY: test
test: target/test/c.stamp \
	target/test/java.stamp

## Setup

android/res target/test target/jvm:
	mkdir -p $@

## Rust

RUST_SRC=Cargo.toml $(wildcard src/*.rs src/*/*.rs src/*/*/*.rs)

target/ssi.h: cbindgen.toml cbindings/build.rs cbindings/Cargo.toml $(RUST_SRC)
	cargo build -p ssi-cbindings
	test -s $@ && touch $@

target/release/libssi.so: $(RUST_SRC)
	cargo build --lib --release
	strip $@

## C

target/test/c.stamp: target/cabi-test target/release/libssi.so | target/test
	target/cabi-test
	touch $@

target/cabi-test: c/test.c target/ssi.h
	$(CC) -Itarget $< -ldl -o $@

## Java

JAVA_SRC=$(wildcard java/*/*.java java/*/*/*.java java/*/*/*/*.java)

target/test/java.stamp: target/jvm/com/spruceid/ssi.class target/release/libssi.so | target/test
	java -Djava.class.path=target/jvm \
		-Djava.library.path=target/release \
		com.spruceid.ssi
	touch $@

target/jvm/com/spruceid/ssi.class: java/com/spruceid/ssi.java | target/jvm
	javac $^ -d target/jvm -source 1.7 -target 1.7

target/com_spruceid_ssi.h: java/com/spruceid/ssi.java
	javac -h target $<

target/ssi.jar: target/jvm/com/spruceid/ssi.class
	jar -cf $@ -C target/jvm $(patsubst target/jvm/%,%,$^)

## Cleanup

.PHONY: clean
clean:
	cargo clean
