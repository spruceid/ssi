# SSI - Java

Java bindings for SSI, using [JNI][]. The [JAR][] file includes Java class files. To use this in an application, you must also include the shared library (`libssi.so`) in your application in your Java Library Path.

## Build

In the parent directory, run:
```
make target/ssi.jar
```

To build the shared library:
```
make target/release/libssi.so
```

## Android

For Android, you can use the separate [Android library (AAR file)](../android/) which includes the Java class files and compiled shared libraries.

[JAR]: https://en.wikipedia.org/wiki/JAR_(file_format)
[JNI]: https://en.wikipedia.org/wiki/Java_Native_Interface
