#ifndef CLI_CONTROL_H
#define CLI_CONTROL_H

#include <iostream>
#include <string>
#include <fstream>

#include <fmt/core.h>
#include <argparse/argparse.hpp>

#ifdef _WIN32
#include <windows.h>
// Windows下的 get_password_from_console 实现
std::string get_password_from_console(const char* prompt, bool show_asterisk = true) {
    const char BACKSPACE = 8;
    const char RETURN = 13;

    std::string password;
    unsigned char ch = 0;

    std::cout << prompt;
    std::cout.flush();

    DWORD con_mode;
    DWORD dwRead;

    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);

    GetConsoleMode(hIn, &con_mode);
    SetConsoleMode(hIn, con_mode & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT));

    while (ReadConsoleA(hIn, &ch, 1, &dwRead, NULL) && ch != RETURN) {
        if (ch == BACKSPACE) {
            if (password.length() != 0) {
                if (show_asterisk)
                    std::cout << "\b \b";
                password.resize(password.length() - 1);
            }
        } else {
            password += ch;
            if (show_asterisk)
                std::cout << '*';
        }
    }
    std::cout << std::endl;

    // 将控制台模式还原
    SetConsoleMode(hIn, con_mode);

    return password;
}

#elif __linux__ || __unix__ || __posix__ || __APPLE__
#include <termios.h>
#include <unistd.h>
// Linux下的 get_password_from_console 实现
std::string get_password_from_console(const char* prompt, bool show_asterisk = true) {
    const char BACKSPACE = 127;
    const char RETURN = 10;

    std::string password;
    unsigned char ch = 0;

    std::cout << prompt;
    std::cout.flush();

    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    struct termios tty_orig = tty;
    tty.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);

    while (read(STDIN_FILENO, &ch, 1) && ch != RETURN) {
        if (ch == BACKSPACE) {
            if (password.length() != 0) {
                if (show_asterisk)
                    std::cout << "\b \b";
                password.resize(password.length() - 1);
            }
        } else {
            password += ch;
            if (show_asterisk)
                std::cout << '*';
        }
    }
    std::cout << std::endl;

    // 将终端属性还原
    tcsetattr(STDIN_FILENO, TCSANOW, &tty_orig);

    return password;
}
#endif  // Architecture ifdef

void arg_parser(int argc, char* argv[], std::string& action, std::string& username, std::string& password) {
    argparse::ArgumentParser program("bitsrun_login", "1.0.0");
    program.add_argument("-a", "--action").help("Action = login or logout.").default_value("login");
    program.add_argument("-u", "--username").help("Your username.");
    program.add_argument("-p", "--password").help("Your password.");
    program.add_argument("-d", "--data").help("The ASCII data file storing the username and password. Format: <username>\\n<password>");
    program.add_description("BIT Srun login/logout tool by Cpt.KK");

    program.parse_args(argc, argv);
    
    // Get action
    action = program.get<std::string>("--action");

    if (action != "login" && action != "logout") {
        throw std::runtime_error(fmt::format("Unknown action {:s}.\n", action));
    }

    if (program.present("--data")) {
        std::string data_path = program.get<std::string>("--data");
        
        // read binary data from file
        std::ifstream data_file(data_path, std::ios::in | std::ios::binary);
        if (!data_file.is_open()) {
            throw std::runtime_error(fmt::format("Cannot open data file {:s}.\n", data_path));
        }

        // read data size
        data_file.seekg(0, std::ios::end);
        std::streamoff data_size = data_file.tellg();
        data_file.seekg(0, std::ios::beg);

        // read data content
        std::istreambuf_iterator<char> beg(data_file), end;
        std::string userpass(beg, end);

        // close file
        data_file.close();

        // get username and password
        auto seperator = userpass.find("\n");
        if (seperator == std::string::npos) {
            throw std::runtime_error("Invalid data file.\n");
        }
        username = userpass.substr(0, seperator);
        password = userpass.substr(seperator + 1);

        if (username.back() == '\r') {
            username.pop_back();
        }
    }

    if (program.present("--username")) {
        username = program.get<std::string>("--username");
    } else if (username.empty()) {
        std::cout << "Please enter your username: ";
        std::cin >> username;
    }

    if (program.present("--password")) {
        password = program.get<std::string>("--password");
    } else if (password.empty()) {
        password = get_password_from_console("Please enter your password: ", false);
    }

    if (!std::regex_match(username, std::regex("\\d{1,20}"))) {
        throw std::runtime_error(fmt::format("Invalid username {:s}. It must be digits.\n", username));
    }

    if (password.length() < 8 || password.length() > 16) {
        throw std::runtime_error(fmt::format("Password must be between 8 and 16 characters.\n"));
    }

    return;
}

#endif  // CLI_CONTROL_H