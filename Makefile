# ssi/Makefile

.PHONY: test
test: target/test/c.stamp \
	target/test/java.stamp \
	target/test/aar.stamp \
	target/test/flutter.stamp

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

## Android

.PHONY: install-rustup-android
install-rustup-android:
	rustup target add i686-linux-android armv7-linux-androideabi aarch64-linux-android x86_64-linux-android

ANDROID_SDK_ROOT ?= ~/Android/Sdk
ANDROID_TOOLS ?= $(lastword $(wildcard $(ANDROID_SDK_ROOT)/build-tools/*))
ANDROID_NDK_HOME ?= $(lastword $(wildcard \
					$(ANDROID_SDK_ROOT)/ndk/* \
					$(ANDROID_SDK_ROOT)/ndk-bundle))
OS_NAME=$(shell uname | tr '[:upper:]' '[:lower:]')
TOOLCHAIN=$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/$(OS_NAME)-x86_64
ANDROID_LIBS=\
	target/i686-linux-android/release/libssi.so\
	target/armv7-linux-androideabi/release/libssi.so\
	target/aarch64-linux-android/release/libssi.so\
	target/x86_64-linux-android/release/libssi.so

target/test/aar.stamp: target/ssi.aar | target/test
	rm -rf tmp/test-aar
	mkdir -p tmp/test-aar
	cd tmp/test-aar && unzip -q ../../$<
	cd tmp/test-aar && unzip -qo classes.jar com/spruceid/ssi.class
	javap tmp/test-aar/com/spruceid/ssi.class | grep -q 'public class com.spruceid.ssi'
	touch $@

target/ssi.aar: target/ssi.jar android/AndroidManifest.xml android/R.txt $(ANDROID_LIBS) | android/res
	$(ANDROID_TOOLS)/aapt package -f -S android/res -F $@ --ignore-assets '.*:*~:README.md' android

target/%/release/libssi.so: $(RUST_SRC)
	PATH=$(TOOLCHAIN)/bin:$(PATH) \
	cargo build --lib --release --target $*
	$(TOOLCHAIN)/bin/llvm-strip $@

## Flutter

target/test/flutter.stamp: flutter/lib/ssi.dart target/release/libssi.so | target/test
	cd flutter && LD_LIBRARY_PATH=$(PWD)/flutter \
		flutter --suppress-analytics test
	touch $@

## Cleanup

.PHONY: clean
clean:
	cargo clean
