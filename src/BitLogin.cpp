#include "BitLogin.hpp"

int main(int argc, char *argv[]) {
    int ret = -1;
    std::string action;
    std::string username;
    std::string password;

    try { 
        // Parse input arguments
        arg_parser(argc, argv, action, username, password);

        // Do action
        BitSrunUser user(username, password);
        if (action == "login") {
            user.login();
        } else if (action == "logout") {
            user.logout();
        } else if (action == "save") {
            printf("Saving encoded info to [userdata.dat] at current directory...\n");
            save_string_to_file("userdata.dat", base64::to_base64(username + "\n" + password));
            printf("Save successfully!\n");
        }
        
        ret = 0;
        
    } catch(std::exception& e) {
        printf("Error: %s\n", e.what());

        ret = 1;
    } catch(...) {
        printf("Unknown error!\n");
        ret = 2;
    }

    // Cleaning
    secure_clear_string(username);
    secure_clear_string(password);
    printf("Exiting...\n");
    return ret; 
}