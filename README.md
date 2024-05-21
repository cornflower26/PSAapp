# PSAapp README

Welcome to the **PSAapp** repository! This project implements a PSA (Privacy-preserving Statistical Analysis) application using the **OpenFHE** library for homomorphic encryption.

## 📋 Requirements

To build and run this project, you will need the following:

- **CMake** (minimum required version: 3.26)
- **C++ Compiler** supporting C++17
- **OpenFHE** library (installed in `/usr/local/lib`)
- **Ninja** build system
- **macOS** or **Linux** operating system
- **Command Line Tools** for macOS or equivalent development tools for Linux

## 🛠️ Installation

Follow these steps to set up and build the project:

### Clone the Repository

```sh
git clone https://github.com/cornflower26/PSAapp.git
cd PSAapp
```

### Configure the Build

For **macOS**:

```sh
/Applications/CLion.app/Contents/bin/cmake/mac/bin/cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_MAKE_PROGRAM=/Applications/CLion.app/Contents/bin/ninja/mac/ninja -DHAVE_CXX_FLAG_STD_CXX11=ON -DHAVE_CXX_FLAG_WALL=ON -DHAVE_CXX_FLAG_STD_WEXTRA=ON -DHAVE_CXX_FLAG_WSHADOW=ON -DHAVE_CXX_FLAG_WERROR=ON -DHAVE_STD_REGEX=ON -DHAVE_GNU_POSIX_REGEX=ON -DHAVE_CXX_FLAG_STD_WEXTRA=ON -DHAVE_POSIX_REGEX=ON -DHAVE_STEADY_CLOCK=ON -G Ninja -S ./ -B ./cmake-build-local
```

For **Linux**:

```sh
/usr/bin/cmake --no-warn-unused-cli -DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=TRUE -DCMAKE_BUILD_TYPE:STRING=Debug -DCMAKE_C_COMPILER:FILEPATH=/usr/bin/x86_64-linux-gnu-gcc-7 -DCMAKE_CXX_COMPILER:FILEPATH=/usr/bin/x86_64-linux-gnu-g++-7 -H./ -B./build -G Ninja
```

### Build the Project

```sh
ninja -C ./cmake-build-local
```

## 📖 Introduction

The **PSAapp** is designed to perform privacy-preserving statistical analysis using homomorphic encryption. It leverages the **OpenFHE** library to encrypt, decrypt, and perform computations on encrypted data. This ensures that sensitive data remains secure during the analysis process.

### Main Components

- **PSA-base-scheme.h/cpp**: Defines the base class for the PSA scheme, including key generation and encryption/decryption methods.
- **PSA-cryptocontext.h/cpp**: Manages the cryptographic context and parameters for the PSA scheme.
- **slaprns-scheme.h/cpp**: Implements the SLAP (Secure Lattice-based Aggregation Protocol) scheme, which extends the base PSA scheme with specific encryption and decryption methods.
- **utils.cpp**: Contains utility functions used across the project.

## ⚙️ Configuration

The project uses **CMake** for build configuration. Below are key configuration settings used in the `CMakeLists.txt`:

```cmake
cmake_minimum_required(VERSION 3.26)
project(SLAP)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fopenmp")
set(CMAKE_BUILD_TYPE Debug)

add_executable(SLAP main.cpp
        PSA-base-scheme.h
        PSA-constants.h
        slaprns-scheme.h
        PSA-cryptocontext.h
        dgsampler.h
        slaprns-scheme.cpp
        PSA-cryptocontext.cpp
        PSA-base-scheme.cpp
        utils.cpp)

add_library(openfhecorelib SHARED IMPORTED)
add_library(openfhepkelib SHARED IMPORTED)

set_target_properties(openfhecorelib PROPERTIES IMPORTED_LOCATION "/usr/local/lib/libOPENFHEpke.so")
set_target_properties(openfhecorelib PROPERTIES IMPORTED_LOCATION "/usr/local/lib/libOPENFHEcore.so")

include_directories("/usr/local/include/openfhe")
include_directories("/usr/local/include/openfhe/core")
include_directories("/usr/local/include/openfhe/pke")
include_directories("/usr/local/include/openfhe/binfhe")

link_directories("/usr/local/lib")
link_directories("/usr/include")

target_link_libraries(SLAP OPENFHEcore)
target_link_libraries(SLAP OPENFHEpke)
target_link_libraries(SLAP OPENFHEbinfhe)

set(CMAKE_PREFIX_PATH "/usr/local/lib/OpenFHE")
find_package("OpenFHE")
```

### Important Notes

- Ensure that the **OpenFHE** library is correctly installed and its paths are set in the `CMakeLists.txt`.
- The project uses **Ninja** as the build system, which is specified in the configuration commands.

## 🎉 Usage

After building the project, you can run the executable to perform privacy-preserving statistical analysis:

```sh
./cmake-build-local/SLAP
```

## 🧩 Additional Information

- **PSA-base-scheme.h/cpp**: Contains the base implementation of the PSA scheme, including methods for key generation, encryption, and decryption.
- **PSA-cryptocontext.h/cpp**: Manages cryptographic parameters and context for the PSA scheme, including methods for parameter calculation and scheme initialization.
- **slaprns-scheme.h/cpp**: Implements the SLAP scheme, providing specific methods for encrypting and decrypting polynomials under the PSA framework.
- **utils.cpp**: Provides utility functions such as Hamming weight calculation and polynomial encoding/decoding.

For detailed implementation and usage, refer to the source files in the repository.

---

Feel free to contribute to the project by submitting issues or pull requests on the GitHub repository. Happy coding! 🚀