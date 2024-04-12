#include "BitSrunUser.hpp" 
#include "BitLogin.hpp"

int main(int argc, char *argv[]) {

    try { 
        // Parse input arguments
        std::string action;
        std::string username;
        std::string password;
        
        arg_parser(argc, argv, action, username, password);


        // Do action
        BitSrunUser user(username, password);
        if (action == "login") {
            user.login();
        } else if (action == "logout") {
            user.logout();
        }

        secure_clear_string(password);

    } catch(std::exception& e) {
        fmt::print(fg(fmt::color::crimson), "Error: {}\n", e.what());
        return 1;
    } catch(...) {
        fmt::print(fg(fmt::color::crimson), "Unknown error!\n");
        return 1;
    }

    return 0; 
}