#ifndef BIT_LOGIN_H
#define BIT_LOGIN_H

#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#include <argparse/argparse.hpp>

#include "BitSrunUser.hpp"
#include "project.h"
#include "base64.hpp"

// Declaration
std::string get_password_from_console(const char* prompt, bool show_asterisk = true);
void get_userpass_from_file(const std::string& data_path, std::string& username, std::string& password);
void arg_parser(int argc, char* argv[], std::string& action, std::string& username, std::string& password);

#ifdef _WIN32
#include <windows.h>

// RAII wrapper for Windows console mode
class WindowsConsoleModeGuard {
public:
    explicit WindowsConsoleModeGuard(HANDLE hConsole, DWORD newMode) : hConsole_(hConsole), oldMode_(0) {
        if (!GetConsoleMode(hConsole_, &oldMode_)) {
            // If GetConsoleMode fails, we can't restore, but we'll note it.
            // This might happen if input is redirected.
            canRestore_ = false;
        } else {
            canRestore_ = true;
            if (!SetConsoleMode(hConsole_, newMode)) {
                // Failed to set new mode, mark that we shouldn't try to restore to a mode we didn't set
                canRestore_ = false;
            }
        }
    }

    ~WindowsConsoleModeGuard() {
        if (canRestore_) {
            SetConsoleMode(hConsole_, oldMode_);
        }
    }

    // Prevent copying
    WindowsConsoleModeGuard(const WindowsConsoleModeGuard&) = delete;
    WindowsConsoleModeGuard& operator=(const WindowsConsoleModeGuard&) = delete;

private:
    HANDLE hConsole_;
    DWORD oldMode_;
    bool canRestore_;
};

// Windows: get_password_from_console
std::string get_password_from_console(const char* prompt, bool show_asterisk) {
    const char BACKSPACE = 8;
    const char RETURN = 13;

    std::string password;
    unsigned char ch = 0;

    std::cout << prompt;
    std::cout.flush();

    DWORD dwRead;
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);

    // Use RAII guard to manage console mode
    WindowsConsoleModeGuard modeGuard(hIn, 
        []() { // Get current mode and modify it
            DWORD currentMode;
            HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
            if (GetConsoleMode(h, &currentMode)) {
                return currentMode & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT);
            }
            return DWORD(0); // Return 0 if failed to get mode, SetConsoleMode will fail gracefully
        }()
    );
    // modeGuard will automatically restore the original mode when it goes out of scope

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

    return password;
}

#elif __linux__ || __unix__ || __posix__ || __APPLE__
#include <termios.h>
#include <unistd.h>

// RAII wrapper for Unix terminal mode
class UnixTerminalModeGuard {
public:
    explicit UnixTerminalModeGuard(int fd) : fd_(fd), isValid_(false) {
        if (tcgetattr(fd_, &oldTermios_) == 0) {
            isValid_ = true;
            struct termios newTermios = oldTermios_;
            newTermios.c_lflag &= ~(ICANON | ECHO);
            if (tcsetattr(fd_, TCSANOW, &newTermios) != 0) {
                // Failed to set new mode, mark invalid
                isValid_ = false;
            }
        }
        // If tcgetattr fails, isValid_ remains false, and destructor will do nothing
    }

    ~UnixTerminalModeGuard() {
        if (isValid_) {
            tcsetattr(fd_, TCSANOW, &oldTermios_);
        }
    }

    // Prevent copying
    UnixTerminalModeGuard(const UnixTerminalModeGuard&) = delete;
    UnixTerminalModeGuard& operator=(const UnixTerminalModeGuard&) = delete;

private:
    int fd_;
    struct termios oldTermios_;
    bool isValid_;
};

// Linux & Apple: get_password_from_console
std::string get_password_from_console(const char* prompt, bool show_asterisk) {
    const char BACKSPACE = 127;
    const char RETURN = 10;

    std::string password;
    unsigned char ch = 0;

    std::cout << prompt;
    std::cout.flush();

    // Use RAII guard to manage terminal mode
    UnixTerminalModeGuard modeGuard(STDIN_FILENO);
    // modeGuard will automatically restore the original mode when it goes out of scope

    while (read(STDIN_FILENO, &ch, 1) > 0 && ch != RETURN) {
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

    return password;
}
#endif  // Architecture ifdef

void get_userpass_from_file(const std::string& data_path, std::string& username, std::string& password) {
    // open file
    std::ifstream data_file(data_path, std::ios::in);
    if (!data_file.is_open()) {
        throw std::runtime_error("Cannot open data file " + data_path + ".\n");
    }

    // read file size
    data_file.seekg(0, std::ios::end);
    std::streamoff data_size = data_file.tellg();
    data_file.seekg(0, std::ios::beg);

    // read content
    std::istreambuf_iterator<char> beg(data_file), end;
    std::string encoded_string(beg, end);

    // close file
    data_file.close();

    // get username and password
    std::string decoded_string = base64::from_base64(encoded_string);
    auto seperator = decoded_string.find("\n");
    if (seperator == std::string::npos) {
        throw std::runtime_error("Invalid data file.\n");
    }
    username = decoded_string.substr(0, seperator);
    password = decoded_string.substr(seperator + 1);

    // Remove possible trailing \r characters
    if (!username.empty() && username.back() == '\r') {
        username.pop_back();
    }
    if (!password.empty() && password.back() == '\r') {
        password.pop_back();
    }

}

void save_string_to_file(const std::string& data_path, const std::string& data) {
    std::ofstream data_file(data_path, std::ios::out);
    if (!data_file.is_open()) {
        throw std::runtime_error("Cannot save to [" + data_path + "]. Please save the following string:\n\n" + data + "\n\nto where you can find it.");
    }

    data_file.write(data.c_str(), data.size());
    data_file.close();
}

void arg_parser(int argc, char* argv[], std::string& action, std::string& username, std::string& password) {

    argparse::ArgumentParser program(PROJECT_NAME, PROJECT_STR);
    program.add_argument("-a", "--action").help("Action = login, logout or save.").default_value("login");
    program.add_argument("-u", "--username").help("Your username.");
    program.add_argument("-p", "--password").help("Your password.");
    program.add_argument("-d", "--data").help("The base64 encoded data file storing the username and password.");
    program.add_description(PROJECT_DEF);
    program.add_epilog(PROJECT_COPY);

    // If no arguments provided, show help
    if (argc == 1) {
        std::cout << program;  // This outputs the help message
        exit(0);  // Exit after showing help
    }

    program.parse_args(argc, argv);

    // Get input arguments
    action = program.get<std::string>("--action");
    if (program.present("--data")) {
        get_userpass_from_file(program.get<std::string>("--data"), username, password);
    } else if (program.present("--username") && program.present("--password")) {
        username = program.get<std::string>("--username");
        password = program.get<std::string>("--password");
    } else if (program.present("--username")) {
        username = program.get<std::string>("--username");
        password = get_password_from_console("Please enter your password: ", false);
    } else if (program.present("--password")) {
        username = program.get<std::string>("--password");
        std::cout << "Please enter your username: ";
        std::cin >> username;
    } else {
        std::cout << "Please enter your username: ";
        std::cin >> username;
        password = get_password_from_console("Please enter your password: ", false);
    }

    // Check inputs
    if (action != "login" && action != "logout" && action != "save") {
        throw std::runtime_error("Unknown action " + action + ".\n");
    }

    if (!std::regex_match(username, std::regex("\\d{1,20}"))) {
        throw std::runtime_error("Invalid username " + username + ". It must be digits.\n");
    }

    if (password.length() < 8 || password.length() > 16) {
        throw std::runtime_error("Password must be between 8 and 16 characters.\n");
    }
    
    return;
}

#endif  // BIT_LOGIN_H