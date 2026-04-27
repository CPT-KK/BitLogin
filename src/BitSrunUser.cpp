#include "BitSrunUser.hpp"
#include <unordered_map>

static std::string translate_error(const std::string& code, bool* found = nullptr) {
    static const std::unordered_map<std::string, std::pair<std::string, std::string>> error_map = {
        {"ok",                      {"下线成功",                       "Logout Success"}},
        {"logout_ok",               {"强制下线成功",                    "DM Logout Success"}},
        {"E0000",                   {"登录成功",                       "Login Success"}},
        {"E2531",                   {"用户不存在",                     "Account does not exist"}},
        {"E2532",                   {"两次认证间隔太短，请稍候10秒",    "Authentication interval too short, wait 10s"}},
        {"E2533",                   {"密码错误次数超限，请5分钟后重试",  "Too many wrong passwords, retry in 5 min"}},
        {"E2534",                   {"有代理行为被暂时禁用",            "Proxy behavior detected and disabled"}},
        {"E2553",                   {"帐号或密码错误",                  "Account or password error"}},
        {"E2606",                   {"用户被禁用",                     "User is disabled"}},
        {"E2614",                   {"MAC地址绑定错误",                 "MAC address binding error"}},
        {"E2615",                   {"IP地址绑定错误",                  "IP address binding error"}},
        {"E2616",                   {"用户已欠费",                     "Account in arrears"}},
        {"E2620",                   {"已经在线了",                     "Already online"}},
        {"E2621",                   {"已达到授权人数上限",              "Max concurrent users reached"}},
        {"E6500",                   {"认证程序未启动",                  "Auth service not started"}},
        {"E6506",                   {"用户名或密码错误",                "Username or password error"}},
        {"E6508",                   {"已欠费，请尽快充值",              "Arrears, please recharge"}},
        {"E6516",                   {"流量已用尽",                     "Data quota exhausted"}},
        {"E6517",                   {"时长已用尽",                     "Time quota exhausted"}},
        {"E6520",                   {"帐号已禁用",                     "Account disabled"}},
        {"ChallengeExpireError",    {"Challenge时间戳错误",             "Challenge timestamp error"}},
        {"SignError",               {"签名错误",                       "Signature error"}},
        {"NotOnlineError",          {"当前设备不在线",                  "Device not online"}},
        {"VcodeError",              {"验证码错误",                      "Verification code error"}},
        {"SpeedLimitError",         {"认证请求太频繁，请稍后10s",       "Auth requests too frequent, wait 10s"}},
        {"IpAlreadyOnlineError",    {"本机IP已使用其他账号在线",         "IP already online with another account"}},
        {"NoResponseDataError",     {"无响应数据",                      "No response data"}},
        {"MemoryDbError",           {"认证服务无响应",                  "Auth service no response"}},
    };
    std::unordered_map<std::string, std::pair<std::string, std::string>>::const_iterator it = error_map.find(code);
    if (it != error_map.end()) {
        if (found) *found = true;
        return "[" + code + " " + it->second.first + " | " + it->second.second + "]";
    }
    if (found) *found = false;
    return "[" + code + "]";
}

static std::string resolve_error_code(const std::string& ecode, const std::string& error, const std::string& error_msg) {
    if (ecode.empty() || ecode.find_first_not_of("0123456789") == std::string::npos) {
        return error_msg.empty() ? error : error_msg;
    }
    if (ecode == "E2901") {
        return error_msg.empty() ? ecode : error_msg;
    }
    return ecode;
}

static void dump_debug_info(const std::string& path, const httplib::Params& params,
                             const httplib::Result& res, const std::string& body_override = "") {
    fprintf(stderr, "\n--- Debug Info ---\n");
    fprintf(stderr, "Request: GET %s\n", path.c_str());
    fprintf(stderr, "Params:\n");
    for (const auto& [key, value] : params) {
        fprintf(stderr, "  %s: %s\n", key.c_str(), value.c_str());
    }
    if (res) {
        fprintf(stderr, "Response status: %d\n", res->status);
        fprintf(stderr, "Response headers:\n");
        for (const auto& [key, value] : res->headers) {
            fprintf(stderr, "  %s: %s\n", key.c_str(), value.c_str());
        }
        fprintf(stderr, "Response body: %s\n", body_override.empty() ? res->body.c_str() : body_override.c_str());
    }
    fprintf(stderr, "--- End Debug Info ---\n\n");
}

void secure_clear_string(std::string& str) {
    volatile char* p = &str[0];
    for (size_t i = 0; i < str.size(); ++i) {
        p[i] = 0;
    }
    str.clear();
}

BitSrunUser::BitSrunUser(const std::string &username, const std::string &password, bool debug) : username_(username), password_(password), debug_(debug) {
    client_srun_ptr_ = std::make_shared<httplib::Client>("http://10.0.0.55");
    client_srun_ptr_->set_follow_location(true);
    client_srun_ptr_->set_connection_timeout(5, 0);
    client_srun_ptr_->set_read_timeout(5, 0);
    client_srun_ptr_->set_write_timeout(5, 0);

    // initial request to get ac_id
    httplib::Result res_srun = client_srun_ptr_->Get("/");
    check_response_valid_(res_srun, "HTTP error: " + httplib::to_string(res_srun.error()));

    // get ac_id
    ac_id_ = get_params_from_url_(res_srun->location, "ac_id");

    // Check if ac_id was successfully obtained
    if (ac_id_.empty()) {
        throw std::runtime_error("Failed to obtain ac_id from the gateway. The authentication process cannot proceed.");
    }

    // Check current login status and get device `online_ip`
    std::string login_status = get_login_status_();
    ip_ = get_params_from_response_(login_status, "online_ip");
    logged_in_user_ = get_params_from_response_(login_status, "user_name");

    return;
}

BitSrunUser::~BitSrunUser() {};

void BitSrunUser::login() {
    constexpr const char* SRUN_TYPE = "1";
    constexpr const char* SRUN_N = "200";

    // if logged in, return
    if (logged_in_user_ == username_) {
        printf("%s %s\n", translate_error("E2620").c_str(), username_.c_str());
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
    params.emplace("type", SRUN_TYPE);
    params.emplace("n", SRUN_N);

    // prepare login data to generate checksum
    std::string data = "{\"username\":\"" + username_ + "\",\"password\":\"" + password_ + "\",\"acid\":\"" + ac_id_ + "\",\"ip\":\"" + ip_ + "\",\"enc_ver\":\"srun_bx1\"}";

    std::string hmd5 = hmac<MD5>(password_, token);
    std::string info = "{SRBX1}" + fkbase64(xencode(data, token));
    std::string chksum = sha1(token + username_ + token + hmd5 + token + ac_id_ + token + ip_ + token + SRUN_N + token + SRUN_TYPE + token + info);

    // update params with login data, checksum, and encrypted password
    params.emplace("password", "{MD5}" + hmd5);
    params.emplace("chksum", chksum);
    params.emplace("info", info);

    // do post
    httplib::Result res = client_srun_ptr_->Get("/cgi-bin/srun_portal", params, httplib::Headers{});
    check_response_valid_(res, "Failed to login. Check network connection.");

    std::string error = get_params_from_response_(res->body, "error");
    if (error == "ok") {
        if (debug_) { dump_debug_info("/cgi-bin/srun_portal", params, res); }
        printf("%s %s (%s)\n", translate_error("E0000").c_str(), username_.c_str(), ip_.c_str());
    } else {
        bool found;
        std::string ploy_msg = get_params_from_response_(res->body, "ploy_msg");
        std::string ecode = get_params_from_response_(res->body, "ecode");
        std::string error_msg = get_params_from_response_(res->body, "error_msg");
        std::string resolved = resolve_error_code(ecode, error, error_msg);
        std::string error_code = ploy_msg.empty() ? resolved : ploy_msg;
        std::string msg = translate_error(error_code, &found);
        if (!found || debug_) {
            dump_debug_info("/cgi-bin/srun_portal", params, res);
        }
        throw std::runtime_error(msg);
    }

    secure_clear_string(password_);
    secure_clear_string(data);

    return;
}

void BitSrunUser::logout() {
    // if not logged in, return
    if (logged_in_user_ == "") {
        printf("%s %s\n", translate_error("NotOnlineError").c_str(), username_.c_str());
        return;
    }

    httplib::Params params;
    params.emplace("callback", "jsonp");
    params.emplace("action", "logout");
    params.emplace("ac_id", ac_id_.c_str());
    params.emplace("ip", ip_.c_str());
    params.emplace("username", username_.c_str());

    httplib::Result res = client_srun_ptr_->Get("/cgi-bin/srun_portal", params, httplib::Headers{});
    check_response_valid_(res, "Failed to logout. Check network connection.");

    std::string error = get_params_from_response_(res->body, "error");
    if (error == "ok") {
        if (debug_) { dump_debug_info("/cgi-bin/srun_portal", params, res); }
        printf("%s %s (%s)\n", translate_error("ok").c_str(), username_.c_str(), ip_.c_str());
    } else {
        bool found;
        std::string ecode = get_params_from_response_(res->body, "ecode");
        std::string error_msg = get_params_from_response_(res->body, "error_msg");
        std::string error_code = error.empty() ? std::string("unknown") : resolve_error_code(ecode, error, error_msg);
        std::string msg = translate_error(error_code, &found);
        if (!found || debug_) {
            dump_debug_info("/cgi-bin/srun_portal", params, res);
        }
        throw std::runtime_error(msg);
    }

    return;
}

void BitSrunUser::dm_logout() {
    std::time_t time_val = static_cast<std::time_t>(std::time(nullptr));
    std::string time_str = std::to_string(time_val);
    std::string unbind = "0";
    std::string sign = sha1(time_str + username_ + ip_ + unbind + time_str);

    httplib::Params params;
    params.emplace("callback", "jsonp");
    params.emplace("ip", ip_.c_str());
    params.emplace("username", username_.c_str());
    params.emplace("time", time_str);
    params.emplace("unbind", unbind);
    params.emplace("sign", sign);

    auto res = client_srun_ptr_->Get("/cgi-bin/rad_user_dm", params, httplib::Headers{});
    check_response_valid_(res, "Failed to DM logout. Check network connection.");

    std::string error = get_params_from_response_(res->body, "error");
    if (error == "logout_ok") {
        if (debug_) { dump_debug_info("/cgi-bin/rad_user_dm", params, res); }
        printf("%s %s (%s)\n", translate_error("logout_ok").c_str(), username_.c_str(), ip_.c_str());
    } else {
        bool found;
        std::string ecode = get_params_from_response_(res->body, "ecode");
        std::string error_msg = get_params_from_response_(res->body, "error_msg");
        std::string error_code = error.empty() ? std::string("unknown") : resolve_error_code(ecode, error, error_msg);
        std::string msg = translate_error(error_code, &found);
        if (!found || debug_) {
            dump_debug_info("/cgi-bin/rad_user_dm", params, res);
        }
        throw std::runtime_error(msg);
    }
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

    httplib::Result res = client_srun_ptr_->Get("/cgi-bin/rad_user_info", params, httplib::Headers{});
    check_response_valid_(res, "Failed to get status from 10.0.0.55. Check network connection.");

    if (debug_) { dump_debug_info("/cgi-bin/rad_user_info", params, res); }

    return res->body;
}

std::string BitSrunUser::get_token_() {
    httplib::Params params;
    params.emplace("callback", "jsonp");
    params.emplace("username", username_.c_str());
    params.emplace("ip", ip_.c_str());

    httplib::Result res = client_srun_ptr_->Get("/cgi-bin/get_challenge", params, httplib::Headers{});
    check_response_valid_(res, "Failed to get token from 10.0.0.55. Check network connection.");

    std::string error = get_params_from_response_(res->body, "error");
    if (error != "ok") {
        bool found;
        std::string ecode = get_params_from_response_(res->body, "ecode");
        std::string error_msg = get_params_from_response_(res->body, "error_msg");
        std::string msg = translate_error(resolve_error_code(ecode, error, error_msg), &found);
        if (!found || debug_) {
            dump_debug_info("/cgi-bin/get_challenge", params, res);
        }
        throw std::runtime_error(msg);
    }

    if (debug_) { dump_debug_info("/cgi-bin/get_challenge", params, res); }

    if (ip_.empty()) {
        ip_ = get_params_from_response_(res->body, "client_ip");
    }

    return get_params_from_response_(res->body, "challenge");
};

std::string BitSrunUser::fkbase64(const std::string& raw_s) {
    static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static const std::string custom_chars = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA";

    std::string binary;
    for (char c : raw_s) {
        binary += std::bitset<8>(c).to_string();
    }

    std::string base64_encoded;
    for (size_t i = 0; i < binary.length(); i += 6) {
        std::string segment = binary.substr(i, 6);
        int value = std::stoi(segment, nullptr, 2);
        base64_encoded += base64_chars[value];
    }

    std::string result;
    for (char c : base64_encoded) {
        std::string::size_type pos = base64_chars.find(c);
        result += (pos != std::string::npos) ? custom_chars[pos] : c;
    }

    return result;
}

unsigned int BitSrunUser::ordat(const std::string& msg, size_t idx) {
    if (msg.length() > idx) {
        return static_cast<unsigned char>(msg[idx]);
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
    pwdk.resize(4, 0);

    uint64_t n = pwd.size() - 1;
    uint64_t z = pwd[n];
    uint64_t y = pwd[0];
    uint64_t c = 0x86014019 | 0x183639A0;
    uint64_t m = 0, e = 0, p = 0;
    uint64_t q = static_cast<uint64_t>(6 + 52 / (n + 1));
    uint64_t d = 0;
    while (q > 0) {
        d = (d + c) & (0x8CE0D9BF | 0x731F2640);
        e = d >> 2 & 3;
        for (p = 0; p < n; p++) {
            y = pwd[p + 1];
            m = z >> 5 ^ y << 2;
            m += ((y >> 3 ^ z << 4) ^ (d ^ y)) + (pwdk[(p & 3) ^ e] ^ z);
            pwd[p] = (pwd[p] + m) & (0xEFB8D130 | 0x10472ECF);
            z = pwd[p];
        }
        y = pwd[0];
        m = z >> 5 ^ y << 2;
        m += ((y >> 3 ^ z << 4) ^ (d ^ y)) + (pwdk[(p & 3) ^ e] ^ z);
        pwd[n] = (pwd[n] + m) & (0xBB390742 | 0x44C6F8BD);
        z = pwd[n];
        q--;
    }
    return lencode(pwd, false);
}
