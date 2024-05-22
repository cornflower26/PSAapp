# Project Documentation

👋 Welcome to the PSAapp project! This documentation will guide you through the setup, installation, and usage of the project. Additionally, we'll provide details about the functions and how they work together.

## Table of Contents
1. [Installation and Execution](#installation-and-execution)
2. [Function Details](#function-details)
3. [User Input and Functionality](#user-input-and-functionality)

## Installation and Execution

### Prerequisites

Before you begin, ensure you have the following installed on your system:
- **CMake**: To manage the project's build process.
- **Ninja**: A small build system with a focus on speed.
- **C++ Compiler**: Capable of handling C++17 standard.

### Installation

Follow these steps to set up and build the project:

1. **Clone the Repository**
    ```bash
    git clone <repository-url>
    cd PSAapp
    ```

2. **Generate Build Files**
    Here are the commands based on the operating system:

    **For macOS:**
    ```bash
    /Applications/CLion.app/Contents/bin/cmake/mac/bin/cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_MAKE_PROGRAM=/Applications/CLion.app/Contents/bin/ninja/mac/ninja \
      -DHAVE_CXX_FLAG_STD_CXX11=ON -DHAVE_CXX_FLAG_WALL=ON -DHAVE_CXX_FLAG_STD_WEXTRA=ON \
      -DHAVE_CXX_FLAG_WSHADOW=ON -DHAVE_CXX_FLAG_WERROR=ON -DHAVE_STD_REGEX=ON -DHAVE_GNU_POSIX_REGEX=ON \
      -DHAVE_CXX_FLAG_STD_WEXTRA=ON -DHAVE_POSIX_REGEX=ON -DHAVE_STEADY_CLOCK=ON \
      -G Ninja -S /path/to/PSAapp -B /path/to/PSAapp/cmake-build-local
    ```

    **For Linux:**
    ```bash
    /usr/bin/cmake --no-warn-unused-cli -DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=TRUE \
      -DCMAKE_BUILD_TYPE:STRING=Debug -DCMAKE_C_COMPILER:FILEPATH=/usr/bin/x86_64-linux-gnu-gcc-7 \
      -DCMAKE_CXX_COMPILER:FILEPATH=/usr/bin/x86_64-linux-gnu-g++-7 \
      -H/home/user/PSAapp/ -B/home/user/PSAapp/build -G Ninja
    ```

3. **Build the Project**
    Change to the build directory and run the build command:
    ```bash
    cd cmake-build-local
    ninja
    ```

### Execution

Run the compiled executable with appropriate arguments:
```bash
./SLAP -t <number> -p <number> -n <number> -i <number> -k <number> -N <number>
```

* **Parameters:**
    - `-t`: Log plaintext bits.
    - `-p`: Packing size.
    - `-n`: Number of users.
    - `-i`: Number of iterations.
    - `-k`: Security parameter.
    - `-N`: Some other parameter.

Examples:
```bash
./SLAP -t 16 -p 1 -n 10 -i 1 -k 1 -N 1
```

## Function Details

### Overview

The project consists of several classes and functions designed for performing cryptographic operations. Below are details on the main functions:

### PSA-base-scheme.cpp

- **Class: `PSAScheme`**
    - **Constructor:**
        ```cpp
        PSAScheme::PSAScheme(Scheme scheme, double scale);
        ```
        Initializes the PSA scheme with given parameters.

    - **Function: `PublicKey`**
        ```cpp
        void PSAScheme::PublicKey(DCRTPoly& pk, const uint64_t ts, bool dummy);
        ```
        Generates the public key. If `dummy` is true, it sets pk to zero.

    - **Function: `SecretKey`**
        ```cpp
        void PSAScheme::SecretKey(DCRTPoly& aggregationKey, std::vector<DCRTPoly>& privateKeys, int num_users, bool dummy);
        ```
        Generates the secret keys. It combines individual private keys into a single aggregation key.

### dgsampler.cpp & dgsampler.h

- **Function: `sample_dgauss`**
    ```cpp
    int sample_dgauss(double sigma2, std::mt19937 &rng);
    ```
    Samples a discrete Gaussian distribution with variance `sigma2`.

- **Class: `DiscreteLaplacianGenerator`**
    - **Function: `sample_uniform`**
        ```cpp
        int sample_uniform(int m, std::mt19937 &rng);
        ```
        Samples uniformly from the range `[0, m)`.

    - **Function: `u`**
        ```cpp
        int u(const double scale);
        ```
        Calls `sample_uniform` with the provided scale.

### main.cpp

- **Main Function:**
    ```cpp
    int main(int argc, char **argv);
    ```
    Entry point of the application. Parses command-line arguments and initializes parameters for the scheme.

## User Input and Functionality

### Input Parameters

The program takes several input parameters through the command line, which are key to its operation:

- **`-t <number>`**: Specifies the number of bits for plaintext space (`plain_bits`). Must be non-zero.
- **`-p <number>`**: Defines the packing size (`packing_size`). Determines how data is packed.
- **`-n <number>`**: Sets the number of users (`num_users`). Must be at least 1.
- **`-i <number>`**: Indicates the number of iterations (`iters`). Must be at least 1.
- **`-k <number>`**: A security-related parameter (`k_prime`).
- **`-N <number>`**: Another parameter (`N`).

### Execution Flow

1. **Setup**: Parse the input parameters from the command line and validate them.
2. **Initialization**: Initialize keys and parameters using the parsed values.
3. **Execution**: Run the cryptographic operations as per the given scheme and parameters.

### Example Command
```bash
./SLAP -t 16 -p 1 -n 10 -i 1 -k 1 -N 1
```
This command sets up a PSA scheme with a plaintext space of 16 bits, packing size of 1, 10 users, 1 iteration, and specified values for `k_prime` and `N`.

## Conclusion

This documentation has covered the essential aspects of installing, executing, and understanding the functions in the PSAapp project. Please refer to the source code files for detailed implementation【4:0†source】.