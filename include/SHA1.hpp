#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdint>

class SHA1 {
public:
    SHA1();
    void update(const std::string& input);
    std::string hexdigest();
    SHA1& finalize();

private:
    void transform(const uint8_t block[64]);
    static void encode(uint8_t output[], const uint32_t input[], size_t len);
    static void decode(uint32_t output[], const uint8_t input[], size_t len);
    static void memset(uint8_t* output, uint8_t value, size_t len);

    uint32_t state[5];
    uint64_t count;
    uint8_t buffer[64];
    uint8_t digest[20];
    bool finalized;

    static const uint8_t PADDING[64];
    static const char HEX[16];
};

const uint8_t SHA1::PADDING[64] = { 0x80 };
const char SHA1::HEX[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

SHA1::SHA1() {
    finalized = false;
    count = 0;
    state[0] = 0x67452301;
    state[1] = 0xEFCDAB89;
    state[2] = 0x98BADCFE;
    state[3] = 0x10325476;
    state[4] = 0xC3D2E1F0;
}

void SHA1::update(const std::string& input) {
    const uint8_t* data = reinterpret_cast<const uint8_t*>(input.c_str());
    size_t len = input.length();
    size_t i = 0, index = count / 8 % 64;

    if ((count += len << 3) < (len << 3)) {
        throw std::runtime_error("SHA1: message too long");
    }

    size_t partLen = 64 - index;

    if (len >= partLen) {
        memcpy(&buffer[index], data, partLen);
        transform(buffer);

        for (i = partLen; i + 63 < len; i += 64) {
            transform(&data[i]);
        }

        index = 0;
    } else {
        i = 0;
    }

    memcpy(&buffer[index], &data[i], len - i);
}

SHA1& SHA1::finalize() {
    if (!finalized) {
        uint8_t bits[8];
        encode(bits, reinterpret_cast<uint32_t*>(&count), 8);

        size_t index = count / 8 % 64;
        size_t padLen = (index < 56) ? (56 - index) : (120 - index);
        update(std::string(reinterpret_cast<const char*>(PADDING), padLen));
        update(std::string(reinterpret_cast<const char*>(bits), 8));

        encode(digest, state, 20);

        finalized = true;
    }
    return *this;
}

void SHA1::transform(const uint8_t block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4], t, w[80];

    decode(w, block, 64);

    for (size_t i = 16; i < 80; ++i) {
        w[i] = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16];
        w[i] = (w[i] << 1) | (w[i] >> 31);
    }

    for (size_t i = 0; i < 80; ++i) {
        if (i < 20) {
            t = ((b & c) | ((~b) & d)) + 0x5A827999;
        } else if (i < 40) {
            t = (b ^ c ^ d) + 0x6ED9EBA1;
        } else if (i < 60) {
            t = ((b & c) | (b & d) | (c & d)) + 0x8F1BBCDC;
        } else {
            t = (b ^ c ^ d) + 0xCA62C1D6;
        }
        t += ((a << 5) | (a >> 27)) + e + w[i];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = t;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

void SHA1::encode(uint8_t output[], const uint32_t input[], size_t len) {
    for (size_t i = 0, j = 0; j < len; ++i, j += 4) {
        output[j] = (input[i] >> 24) & 0xFF;
        output[j + 1] = (input[i] >> 16) & 0xFF;
        output[j + 2] = (input[i] >> 8) & 0xFF;
        output[j + 3] = input[i] & 0xFF;
    }
}

void SHA1::decode(uint32_t output[], const uint8_t input[], size_t len) {
    for (size_t i = 0, j = 0; j < len; ++i, j += 4) {
        output[i] = ((uint32_t)input[j + 3]) | (((uint32_t)input[j + 2]) << 8) |
                    (((uint32_t)input[j + 1]) << 16) | (((uint32_t)input[j]) << 24);
    }
}

std::string SHA1::hexdigest() {
    if (!finalized) {
        finalize();
    }

    std::ostringstream result;
    for (int i = 0; i < 20; ++i) {
        result << HEX[(digest[i] >> 4) & 0x0F] << HEX[digest[i] & 0x0F];
    }

    return result.str();
}
