﻿#ifndef BITSRUN_USER_H
#define BITSRUN_USER_H

#include <iostream>
#include <string>
#include <regex>
#include <vector>
#include <algorithm>
#include <bitset>

#include <httplib.h>

#include "sha1.h"
#include "hmac.h"
#include "md5.h"

#define _TYPE_CONST "1"
#define _N_CONST "200"

void secure_clear_string(std::string& str);

class BitSrunUser {
public:
    BitSrunUser(const std::string &username, const std::string &password);
    ~BitSrunUser();

    void login();
    void logout();

private:
    std::shared_ptr<httplib::Client> client_srun_ptr_;
    std::shared_ptr<httplib::Client> client_valid_ptr_;

    std::string username_;
    std::string password_;
    std::string ac_id_;
    std::string ip_;
    std::string logged_in_user_;

    inline void check_response_valid_(const httplib::Result& res, const std::string& error_prompt);
    inline std::string get_params_from_url_(const std::string& url, const std::string& paramName);
    inline std::string get_params_from_response_(const std::string& input, const std::string& paramName);
    std::string get_login_status_();
    std::string get_token_();

    std::string fkbase64(const std::string& raw_s);
    int ordat(const std::string& msg, size_t idx);
    std::vector<uint64_t> sencode(const std::string& msg, bool key);
    std::string lencode(std::vector<uint64_t>& msg, bool key);
    std::string xencode(const std::string& msg, const std::string& key);

    SHA1 sha1;

};
#endif  // BITSRUN_USER_H   