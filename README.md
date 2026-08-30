# Offline Bytecode Signature Dumper

A small C11 command-line tool that creates masked Java bytecode signatures
without starting a JVM. It accepts a single `.class` file or a complete
`.jar`/`.zip` archive.

Constant-pool indices, branch targets, and switch operands are written as
`??`, so signatures remain usable when those offsets change.

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Dependencies are downloaded through CMake FetchContent:

- [jni2hook](https://github.com/reversedcodes/jni2hook)
- [miniz](https://github.com/richgel999/miniz)

## Usage

```sh
./build/Offline-Bytecode-Signature-Dumper <target.class|target.jar> <output.txt>
```

Each method with a `Code` attribute produces one line:

```text
example.Target.compute(I)I | 1B 06 68 10 07 60 AC
```

The class name, method name, and JVM descriptor uniquely identify overloaded
methods. Abstract and native methods have no bytecode and are skipped.
