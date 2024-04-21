#ifndef BASE64_H
#define BASE64_H
#include <iostream>
#include <string>
#include <vector>

std::string base64_encode(const std::string& input) {
    static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string ret;
    ret.reserve(((input.size() + 2) / 3) * 4);

    size_t i = 0;
    size_t j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    for (const unsigned char c : input) {
        char_array_3[i++] = c;
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (size_t k = 0; k < 4; ++k) {
                ret += base64_chars[char_array_4[k]];
            }
            i = 0;
        }
    }

    if (i > 0) {
        for (size_t k = i; k < 3; ++k) {
            char_array_3[k] = '\0';
        }

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (size_t k = 0; k < i + 1; ++k) {
            ret += base64_chars[char_array_4[k]];
        }

        while (i++ < 3) {
            ret += '=';
        }
    }

    return ret;
}

std::vector<uint8_t> base64_decode(const std::string& encoded_string) {
    static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    if (encoded_string.empty() || (encoded_string.size() % 4 != 0)) {
        throw std::runtime_error("Invalid Base64 encoded string length");
    }

    std::vector<uint8_t> ret;
    ret.reserve((encoded_string.size() / 4) * 3);

    size_t i = 0;
    size_t j = 0;
    int val[4] = {0};

    for (const char c : encoded_string) {
        if (c != '=') {
            val[j++] = static_cast<int>(base64_chars.find(c));
        }

        if (j == 4) {
            ret.push_back((val[0] << 2) + ((val[1] & 0x30) >> 4));
            if (encoded_string[i + 2] != '=') {
                ret.push_back(((val[1] & 0xf) << 4) + ((val[2] & 0x3c) >> 2));
            }
            if (encoded_string[i + 3] != '=') {
                ret.push_back(((val[2] & 0x3) << 6) + val[3]);
            }
            j = 0;
        }

        ++i;
    }

    return ret;
}
#endif  // BASE64_H