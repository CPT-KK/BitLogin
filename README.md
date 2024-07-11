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
- `-a`, 或 `--action`: 指定动作为 login，save，或 logout。未指定时，默认 login
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
- （**生成base64 编码的账号密码文件**） `BitLogin -a save -u 1120240000 -p abcdef123456`

### 如何提供 `-d` 需要的 base64 编码的文件

1. 使用程序的 `-a save` 功能，示例如上
2. 找一个在线 base64 编解码的网站，例如 [base64encode](https://www.base64encode.org/)。或者，在 Windows 下可以通过命令行的 `certutil` 工具来进行编码，参考 [Microsoft certutil](https://learn.microsoft.com/zh-cn/windows-server/administration/windows-commands/certutil) 和 [Windows下base64编解码命令](https://blog.csdn.net/zhaoxf4/article/details/106957388)。编码前的文本有两行，第一行为用户名，第二行为密码，用换行符分隔

## For development

Notice that the project uses `C+17` standard.

### Prerequisites

This project relies on the following libraries:

- [cpp-httplib](https://github.com/yhirose/cpp-httplib)
- [argparse](https://github.com/p-ranav/argparse)
- [hashpp](https://github.com/D7EAD/HashPlusPlus)
- [base64](https://github.com/tobiaslocker/base64)

> The dependencies are all included in the `include` directory. 