# secure-signer
A app that allows you to sign a document using SHA256 and RSA to varify the signature

## Build Instructions
### 1. **Clone or Download the Source**
Make sure you have the source code in your project directory.
It can be cloned using
```bash
git clone --recursive https://github.com/wba6/secure-signer.git
```

### 2. **Install Dependencies**
Ensure that you have GMP installed on your system. On many Linux distributions, you can install it via your package manager:

- **Ubuntu/Debian:**
  ```bash
  sudo apt-get update
  sudo apt-get install libgmp-dev
  ```

- **Fedora:**
  ```bash
  sudo dnf install gmp-devel
  ```

On **Windows**, you might need to download and install GMP from a trusted source or use vcpkg, and ensure that the headers and libraries are accessible.

### 3. **Create a Build Directory**
It’s a good practice to create a separate directory for out-of-source builds. From your project root directory, run:
```bash
mkdir build
cd build
```

### 4. **Configure the Build**
Run CMake to configure the project. You can do this with:
```bash
cmake ..
```
This command tells CMake to generate the build files in the current directory (`build`) using the `CMakeLists.txt` in the parent directory.

### 5. **Build the Project**
Once configuration is complete, compile the project by running:
```bash
cmake --build .
```
Alternatively, if you prefer using `make`:
```bash
make
```
This will compile the project and produce an executable named `secure_signer`.

### 6. **Run the Executable**
After the build completes, you can run the executable. For example, from the `build` directory:
```bash
./secure_signer
```

**Note:** All files are relative to the executable file

### Troubleshooting
- **GMP Not Found:** If you see errors about GMP not being found, double-check that GMP is installed and that its header and library paths are accessible. You may need to specify additional paths to CMake via `-DGMP_INCLUDE_DIR` and `-DGMP_LIBRARY` options.
- **Compiler Issues:** Ensure that you have a C++ compiler that supports C++17 and that it is properly set up in your environment.
