# BitLogin

BIT 校园网登录登出的 C++ 实现。

This is an C++ implementation of BIT Srun login/logout client.

## 使用说明

程序的调用格式如下：

`bitsrun_login [--help] [--version] [--action VAR] [--username VAR] [--password VAR] [--data VAR]`

其中参数说明如下：

- `-h`, 或 `--help`: 打印帮助信息
- `-a`, 或 `--action`: 指定动作为 login 或 logout，默认为 login
- `-u`, 或 `--username`: BIT Srun 用户名，未指定时程序会要求用户输入
- `-p`, 或 `--password`: BIT Srun 密码，未指定时程序会要求用户输入
- `-d`, 或 `--data`: 从用户给定的 base64 编码文件中加载用户名和密码
    > 为了使用 `-d`，需要提供一个 base64 编码的文件。编码前的文件格式为两行，第一行为用户名，第二行为密码，用换行符分隔（兼容 Windows 的 \r\n 和 Linux、Apple 的 \n）
    >
    > 许多网站提供了在线的 base64 编码功能，例如 [base64encode](https://www.base64encode.org/)，可以使用这些网站将用户名和密码编码为 base64 字符串

示例：

- `BitLogin -a login -u 1120240000 -p abcdef123456`
- `BitLogin --action logout --username 1120240000 --password abcdef123456`
- `BitLogin -u 1120240000`，然后输入密码
- `BitLogin -d D:/data.txt`

## For development

Notice that the project uses `C++20` standard.

### Prerequisites

This project relies on the following libraries:

- [cpp-httplib](https://github.com/yhirose/cpp-httplib)
- [openssl](https://github.com/openssl/openssl)
- [argparse](https://github.com/p-ranav/argparse)
- [fmt](https://github.com/fmtlib/fmt/)

### On Windows

The recommended way to build the project on Windows is to use `vcpkg` and VS Code.

1. Install `vcpkg` via [official installation guidance](https://learn.microsoft.com/vcpkg/get_started/get-started).
    > Please make sure the `vcpkg` is in your `PATH`, and the environment variable `VCPKG_ROOT` is set.
2. Install all the dependencies via `vcpkg`:

    ```shell
    vcpkg install httplib openssl argparse fmt
    ```

3. Open the project in VS Code, and add the following to the workspace `setting.json`. This step is to tell VS Code CMake to use `vcpkg` and its packages. See [here](https://learn.microsoft.com/vcpkg/get_started/get-started) for more details.

    ```json
    {
        "cmake.configureSettings": {
            "CMAKE_TOOLCHAIN_FILE": "C:/path/to/vcpkg/scripts/buildsystems/vcpkg.cmake"
        }
    }
    ```

4. Build the project using the `CMake: Build` command.

### On Linux

It is best to use the native package manager to install the dependencies. Like `apt` on Ubuntu. For openssl and fmt, you can install them using the following command:

```shell
sudo apt install libssl-dev libfmt-dev
```

For the `cpp-httplib` and `argparse`, `FetchContent` in CMake will download them automatically.
