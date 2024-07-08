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
            save_string_to_file("userdata.dat", base64_encode(username + "\n" + password));
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
    for (size_t i = 3; i > 0; i--) {
        printf("Program will exit in %zd seconds...\r", i);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    printf("\n");
    return ret; 
}