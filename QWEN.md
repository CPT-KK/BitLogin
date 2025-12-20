# BitLogin Project Context

## Project Overview

This project, BitLogin, is a C++ implementation of a client for the BIT (Beijing Institute of Technology) Srun campus network gateway login/logout system. It allows users to authenticate with the `10.0.0.55` gateway from Windows, Linux, macOS, and OpenWrt systems.

Key technologies used:
- **Language**: C++17
- **Build Systems**: CMake (primary), Makefile (for OpenWrt)
- **Dependencies**:
  - `cpp-httplib` for HTTP communication.
  - `argparse` for command-line argument parsing.
  - `hash-library` (specifically `md5` and `sha1`) for cryptographic functions.
  - `base64` for encoding/decoding.

The core logic resides in `BitSrunUser.cpp`, which handles the complex SRUN authentication protocol, including challenge-response mechanisms and data encoding. The main entry point is in `BitLogin.cpp`, which parses arguments and invokes the appropriate action (login, logout, save credentials).

## Building and Running

### Prerequisites
- A C++17 compatible compiler.
- CMake (version 3.10 or higher) or Make (for OpenWrt builds).

### Building
- **Using CMake (Recommended for Windows/Linux/macOS)**:
  1. Create a build directory: `mkdir build && cd build`
  2. Configure the project: `cmake ..`
  3. Build the executable: `cmake --build .`
  - The executable will be generated, usually as `build/BitLogin` or `build/Debug/BitLogin.exe`.

- **Using Make (For OpenWrt only)**:
  1. Follow the OpenWrt SDK instructions referenced in the README.
  2. Use the provided `Makefile` to build an `.ipk` package for OpenWrt.

### Running
The built executable (e.g., `BitLogin`) accepts the following arguments:
- `-h`, `--help`: Print help.
- `-v`, `--version`: Print version.
- `-a`, `--action`: Action (`login`, `logout`, `save`). Default is `login`.
- `-u`, `--username`: Your BIT username.
- `-p`, `--password`: Your BIT password.
- `-d`, `--data`: Path to a base64-encoded file containing username and password on separate lines.

**Examples:**
- `BitLogin -u 1120240000 -p mypassword`
- `BitLogin -a logout -u 1120240000`
- `BitLogin -d ./userdata.dat` (where `userdata.dat` contains base64 encoded username and password)

## Development Conventions
- The project uses C++17.
- Source files are in the `src/` directory.
- Header files are in the `include/` directory.
- External library headers are also placed in `include/` (e.g., `argparse`, `httplib`, `hashlib`, `base64`).
- Platform-specific code for password input masking is handled via preprocessor directives in `BitLogin.hpp`.
- Memory for sensitive data (passwords) is cleared after use using `secure_clear_string`.