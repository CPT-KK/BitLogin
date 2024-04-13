# BitLogin

BIT 10.0.0.55 登录登出的 C++ 实现。

This is an C++ implementation of BIT Srun login/logout client.

## 使用说明

### 系统要求

- Windows $\ge$ 10
- Ubuntu $\ge$ 20.04
- macOS $\ge$ 10.12

### 下载与安装

右侧 [Release](https://github.com/CPT-KK/BitLogin/releases) 页面找到对应自己系统架构的可执行文件

### 程序的调用格式

`BitLogin [--help] [--version] [--action VAR] [--username VAR] [--password VAR] [--data VAR]`

其中参数说明如下：

- `-h`, 或 `--help`: 打印帮助信息
- `-v`, 或 `--version`: 打印版本信息
- `-a`, 或 `--action`: 指定动作为 login 或 logout。未指定时，默认 login
- `-d`, 或 `--data`: 从用户给定的 base64 编码文件中加载用户名和密码。指定该参数时，将会忽略 `-u` 和 `-p` 参数的输入（若有）
- `-u`, 或 `--username`: BIT 用户名，未指定此参数且未指定 `-d` 时，程序会要求用户输入
- `-p`, 或 `--password`: BIT 密码，未指定此参数且未指定 `-d` 时，程序会要求用户输入（密码输入不显示在控制台上）

**一般来说，使用 `-d`，或者 `-u` 和 `-p`就可以了**

### 示例

- `BitLogin -a login -u 1120240000 -p abcdef123456`
- `BitLogin --action logout --username 1120240000 --password abcdef123456`
- `BitLogin -u 1120240000`，然后输入密码
- `BitLogin -d D:/data.txt`，其中经 base64 编码后 `data.txt` 的内容为：

    ```plaintext
    MTEyMDI0MDAwMAphYmNkZWYxMjM0NTY=
    ```

    解码后为：

    ```plaintext
    1120240000
    abcdef123456
    ```

### 如何提供 `-d` 需要的 base64 编码的文件

- 找一个在线 base64 编解码的网站，例如 [base64encode](https://www.base64encode.org/)。或者，在 Windows 下可以通过命令行的 `certutil` 工具来进行编码，参考 [Microsoft certutil](https://learn.microsoft.com/zh-cn/windows-server/administration/windows-commands/certutil) 和 [Windows下base64编解码命令](https://blog.csdn.net/zhaoxf4/article/details/106957388)。
- 编码前的文本有两行，第一行为用户名，第二行为密码，用换行符分隔

## For development

Notice that the project uses `C++20` standard.

### Prerequisites

This project relies on the following libraries:

- [cpp-httplib](https://github.com/yhirose/cpp-httplib)
- [openssl](https://github.com/openssl/openssl)
- [argparse](https://github.com/p-ranav/argparse)
- [fmt](https://github.com/fmtlib/fmt/)

> The dependencies `cpp-httplib` and `argparse` are included in the `include` directory. You need to have `openssl` and `fmt` installed on your system.

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

### On Ubuntu

For `openssl` and `fmt`, you can install them using the following command:

```shell
sudo apt install libssl-dev libfmt-dev
```

For other Linux distributions, you can use the corresponding package manager to install the dependencies.

### On macOS

For `openssl` and `fmt`, you can install them using the following command:

```shell
brew install openssl fmt
```
