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
// Windows: get_password_from_console
std::string get_password_from_console(const char* prompt, bool show_asterisk) {
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

    SetConsoleMode(hIn, con_mode);

    return password;
}

#elif __linux__ || __unix__ || __posix__ || __APPLE__
#include <termios.h>
#include <unistd.h>
// Linux & Apple: get_password_from_console
std::string get_password_from_console(const char* prompt, bool show_asterisk) {
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

    tcsetattr(STDIN_FILENO, TCSANOW, &tty_orig);

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
    std::vector<uint8_t> decoded_data = base64_decode(encoded_string);
    std::string decoded_string(decoded_data.begin(), decoded_data.end());
    auto seperator = decoded_string.find("\n");
    if (seperator == std::string::npos) {
        throw std::runtime_error("Invalid data file.\n");
    }
    username = decoded_string.substr(0, seperator);
    password = decoded_string.substr(seperator + 1);

    if (username.back() == '\r') {
        username.pop_back();
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