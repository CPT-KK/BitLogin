#include "BitSrunUser.hpp"

void secure_clear_string(std::string& str) {
    memset(&str[0], 0, str.size());
    str.clear();
}

BitSrunUser::BitSrunUser(const std::string &username, const std::string &password) : username_(username), password_(password) {
    client_srun_ptr_ = std::make_shared<httplib::Client>("http://10.0.0.55");
    client_srun_ptr_->set_follow_location(true);
    client_srun_ptr_->set_connection_timeout(5, 0);
    client_srun_ptr_->set_read_timeout(5, 0);
    client_srun_ptr_->set_write_timeout(5, 0);

    client_valid_ptr_ = std::make_shared<httplib::Client>("http://10.0.6.92"); // www.bit.edu.cn -> 10.0.6.92
    client_valid_ptr_->set_follow_location(true);
    client_valid_ptr_->set_connection_timeout(5, 0);
    client_valid_ptr_->set_read_timeout(5, 0);
    client_valid_ptr_->set_write_timeout(5, 0);

    auto res_srun = client_srun_ptr_->Get("/");
    auto res_valid = client_valid_ptr_->Get("/");
    check_response_valid_(res_srun, "HTTP error: " + httplib::to_string(res_srun.error()));
    check_response_valid_(res_valid, "HTTP error: " + httplib::to_string(res_valid.error()));

    // get ac_id
    if (get_params_from_url_(res_valid->location, "ac_id") != "") {
        ac_id_ = get_params_from_url_(res_valid->location, "ac_id");
    } else {
        ac_id_ = get_params_from_url_(res_srun->location, "ac_id");
    }

    // Check current login status and get device `online_ip`
    std::string login_status = get_login_status_();
    ip_ = get_params_from_response_(login_status, "online_ip");
    logged_in_user_ = get_params_from_response_(login_status, "user_name");

    return;
}

BitSrunUser::~BitSrunUser() {};

void BitSrunUser::login() {
    // if logged in, return
    if (logged_in_user_ == username_) {
        std::cout << fmt::format("User {:s} has already logged in.\n", username_);
        return;
    }

    // get challenge from token
    std::string token = get_token_();

    // prepare params for login request
    httplib::Params params;
    params.emplace("callback", "jsonp");
    params.emplace("username", username_.c_str());
    params.emplace("action", "login");
    params.emplace("ac_id", ac_id_.c_str());
    params.emplace("ip", ip_.c_str());
    params.emplace("type", _TYPE_CONST);
    params.emplace("n", _N_CONST);

    // prepare login data to generate checksum
    std::string data = fmt::format(
        R"({{"username":"{:s}","password":"{:s}","acid":"{:s}","ip":"{:s}","enc_ver":"srun_bx1"}})", 
        username_, password_, ac_id_, ip_
    );

    std::string hmd5 = hmac_md5("", token);
    std::string info = "{SRBX1}" + fkbase64(xencode(data, token));
    std::string chksum = sha1_hex(
        fmt::format("{0}{1}{0}{2}{0}{3}{0}{4}{0}{5}{0}{6}{0}{7}", 
        token, username_, hmd5, ac_id_, ip_, _N_CONST, _TYPE_CONST, info)
    );

    // update params with login data, checksum, and encrypted password
    params.emplace("password", "{MD5}" + hmd5);
    params.emplace("chksum", chksum);
    params.emplace("info", info);

    // do post
    auto res = client_srun_ptr_->Post("/cgi-bin/srun_portal", params);
    check_response_valid_(res, "Failed to login. Check network connection.");
    get_params_from_response_(res->body, "access_token");
    
    // Available: access_token client_ip ecode error error_msg online_ip ploy_msg srun_ver username wallet_balance sysver

    // check if success
    if (get_params_from_response_(res->body, "error") == "ok" &&
        get_params_from_response_(res->body, "username") == username_ &&
        get_params_from_response_(res->body, "online_ip") != "") {
            std::cout << fmt::format("User {:s} logged in with IP {:s}.\n", get_params_from_response_(res->body, "username"), get_params_from_response_(res->body, "online_ip"));
    } else if (get_params_from_response_(res->body, "ploy_msg") != "") {
        throw std::runtime_error(get_params_from_response_(res->body, "ploy_msg"));
    } else if (get_params_from_response_(res->body, "error") != "") {
        throw std::runtime_error(get_params_from_response_(res->body, "error"));
    } else if (get_params_from_response_(res->body, "res") != "") {
        throw std::runtime_error(get_params_from_response_(res->body, "res"));
    } else {
        throw std::runtime_error("Seems like login failed and Srun server returns an unrecognized message. Check network connection.");
    }

    secure_clear_string(password_);
    secure_clear_string(data);

    return;
}

void BitSrunUser::logout() {
    // if not logged in, return
    if (logged_in_user_ == "") {
        std::cout << fmt::format("User {:s} has not logged in.\n", username_);
        return;
    }

    httplib::Params params;
    params.emplace("callback", "jsonp");
    params.emplace("action", "logout");
    params.emplace("ac_id", ac_id_.c_str());
    params.emplace("ip", ip_.c_str());
    params.emplace("username", username_.c_str());

    auto res = client_srun_ptr_->Post("/cgi-bin/srun_portal", params);
    check_response_valid_(res, "Failed to logout. Check network connection.");

    std::cout << fmt::format("User {:s} logged out from IP {:s}.\n", username_, get_params_from_response_(res->body, "online_ip"));

    return;   
}

inline void BitSrunUser::check_response_valid_(const httplib::Result& res, const std::string& error_prompt) {
    if (!res || res->status != httplib::StatusCode::OK_200) {
        throw std::runtime_error(error_prompt);
    }
}

inline std::string BitSrunUser::get_params_from_url_(const std::string& url, const std::string& paramName){
    std::regex pattern("\\b" + paramName + "=([^&]*)"); 
    std::smatch matches; 
    return (std::regex_search(url, matches, pattern) && matches.size() > 1) ? matches[1].str() : ""; 
}

inline std::string BitSrunUser::get_params_from_response_(const std::string& input, const std::string& paramName) {
    std::regex pattern("\"" + paramName + "\":\"([^\"]*)\""); 
    std::smatch matches;
    return (std::regex_search(input, matches, pattern) && matches.size() > 1) ? matches[1].str() : ""; 
}

std::string BitSrunUser::get_login_status_() {
    httplib::Params params{
        { "callback", "jsonp" },
    };

    auto res = client_srun_ptr_->Post("/cgi-bin/rad_user_info", params);
    check_response_valid_(res, "Failed to get status from 10.0.0.55. Check network connection.");

    return res->body;
}

std::string BitSrunUser::get_token_() {
    httplib::Params params;
    params.emplace("callback", "jsonp");
    params.emplace("username", username_.c_str());
    params.emplace("ip", ip_.c_str());

    auto res = client_srun_ptr_->Post("/cgi-bin/get_challenge", params);
    check_response_valid_(res, "Failed to get token from 10.0.0.55. Check network connection.");

    return get_params_from_response_(res->body, "challenge");
};

std::string BitSrunUser::fkbase64(const std::string& raw_s) {
    // Lambda to convert input string to binary form
    auto to_binary = [](const std::string& input) {
        std::string binary;
        for (char c : input) {
            for (int i = 7; i >= 0; --i) {
                binary += ((c >> i) & 1) ? '1' : '0';
            }
        }
        return binary;
    };

    // Convert input string to binary
    std::string binary = to_binary(raw_s);

    // Lambda for converting 6-bit segments to Base64
    auto to_base64 = [&](const std::string& bin) {
        std::string result;
        for (size_t i = 0; i < bin.length(); i += 6) {
            std::string segment = bin.substr(i, 6);
            int value = std::stoi(segment, nullptr, 2);
            result += base64_chars[value];
        }
        return result;
    };

    // Convert binary string to Base64
    std::string base64_encoded = to_base64(binary);

    // Perform custom character replacement
    std::string result;
    for (char c : base64_encoded) {
        auto pos = base64_chars.find(c);
        if (pos != std::string::npos) {
            result += custom_chars[pos];
        } else {
            result += c;
        }
    }

    return result;
}

int BitSrunUser::ordat(const std::string& msg, size_t idx) {
    if (msg.length() > idx) {
        return static_cast<int>(msg[idx]);
    }
    return 0;
}

std::vector<uint64_t> BitSrunUser::sencode(const std::string& msg, bool key) {
    uint64_t msg_len = msg.length();
    std::vector<uint64_t> pwd;
    for (size_t i = 0; i < msg_len; i += 4) {
        pwd.push_back(
            ordat(msg, i) |
            ordat(msg, i + 1) << 8 |
            ordat(msg, i + 2) << 16 |
            ordat(msg, i + 3) << 24
        );
    }
    if (key) {
        pwd.push_back(msg_len);
    }
    return pwd;
}

std::string BitSrunUser::lencode(std::vector<uint64_t>& msg, bool key) {
    uint64_t msg_len = msg.size();
    uint64_t ll = (msg_len - 1) << 2;
    if (key) {
        uint64_t m = msg.back();
        if (m < ll - 3 || m > ll) {
            return "";
        }
        ll = m;
    }
    std::string result;
    for (size_t i : msg) {
        result += static_cast<char>(i & 0xFF);
        result += static_cast<char>((i >> 8) & 0xFF);
        result += static_cast<char>((i >> 16) & 0xFF);
        result += static_cast<char>((i >> 24) & 0xFF);
    }
    return key ? result.substr(0, ll) : result;
}

std::string BitSrunUser::xencode(const std::string& msg, const std::string& key) {
    if (msg.empty()) {
        return "";
    }
    std::vector<uint64_t> pwd = sencode(msg, true);
    std::vector<uint64_t> pwdk = sencode(key, false);
    while (pwdk.size() < 4) {
        pwdk.push_back(0);
    }
    
    uint64_t n = pwd.size() - 1;
    uint64_t z = pwd[n];
    uint64_t y = pwd[0];
    uint64_t c = 0x86014019 | 0x183639A0;
    uint64_t m = 0, e = 0, p = 0;
    uint64_t q = static_cast<uint64_t>(6 + 52 / (n + 1));
    uint64_t d = 0;
    while (q > 0) {
        d = d + c & (0x8CE0D9BF | 0x731F2640);
        e = d >> 2 & 3;
        for (p = 0; p < n; p++) {
            y = pwd[p + 1];
            m = z >> 5 ^ y << 2;
            m += ((y >> 3 ^ z << 4) ^ (d ^ y)) + (pwdk[(p & 3) ^ e] ^ z);
            pwd[p] = pwd[p] + m & (0xEFB8D130 | 0x10472ECF);
            z = pwd[p];
        }
        y = pwd[0];
        m = z >> 5 ^ y << 2;
        m += ((y >> 3 ^ z << 4) ^ (d ^ y)) + (pwdk[(p & 3) ^ e] ^ z);
        pwd[n] = pwd[n] + m & (0xBB390742 | 0x44C6F8BD);
        z = pwd[n];
        q--;
    }
    return lencode(pwd, false);
}

std::string BitSrunUser::hmac_md5(const std::string& data, const std::string& key) {
    unsigned char* result;
    unsigned int len = 16; // MD5 results in 128 bit hash, hence 16 bytes.
    result = (unsigned char*)malloc(sizeof(char) * len);
    
    HMAC(EVP_md5(), key.c_str(), static_cast<int>(key.length()), (unsigned char*)data.c_str(), data.length(), result, &len);

    std::stringstream ss;
    for (unsigned int i = 0; i < len; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (uint64_t)result[i];
    }

    free(result);
    return ss.str();
}

std::string BitSrunUser::sha1_hex(const std::string& input) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char*)input.c_str(), input.length(), hash);
    std::stringstream ss;
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}