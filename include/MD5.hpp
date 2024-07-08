#include <cstring>
#include <iostream>
#include <sstream>
#include <iomanip>

class MD5 {
public:
    MD5();
    void update(const unsigned char* data, size_t length);
    void update(const char* data, size_t length);
    MD5& finalize();
    std::string hexdigest() const;

private:
    void transform(const unsigned char block[64]);
    static void decode(uint32_t output[], const unsigned char input[], size_t len);
    static void encode(unsigned char output[], const uint32_t input[], size_t len);

    bool finalized;
    unsigned char buffer[64];
    uint32_t count[2];
    uint32_t state[4];
    unsigned char digest[16];

    static const unsigned char PADDING[64];
    static const char HEX[16];
    static const uint32_t S11;
    static const uint32_t S12;
    static const uint32_t S13;
    static const uint32_t S14;
    static const uint32_t S21;
    static const uint32_t S22;
    static const uint32_t S23;
    static const uint32_t S24;
    static const uint32_t S31;
    static const uint32_t S32;
    static const uint32_t S33;
    static const uint32_t S34;
    static const uint32_t S41;
    static const uint32_t S42;
    static const uint32_t S43;
    static const uint32_t S44;
    static inline uint32_t F(uint32_t x, uint32_t y, uint32_t z);
    static inline uint32_t G(uint32_t x, uint32_t y, uint32_t z);
    static inline uint32_t H(uint32_t x, uint32_t y, uint32_t z);
    static inline uint32_t I(uint32_t x, uint32_t y, uint32_t z);
    static inline uint32_t rotate_left(uint32_t x, int n);
    static inline void FF(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac);
    static inline void GG(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac);
    static inline void HH(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac);
    static inline void II(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac);
};

const unsigned char MD5::PADDING[64] = { 0x80 };
const char MD5::HEX[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

const uint32_t MD5::S11 = 7;
const uint32_t MD5::S12 = 12;
const uint32_t MD5::S13 = 17;
const uint32_t MD5::S14 = 22;
const uint32_t MD5::S21 = 5;
const uint32_t MD5::S22 = 9;
const uint32_t MD5::S23 = 14;
const uint32_t MD5::S24 = 20;
const uint32_t MD5::S31 = 4;
const uint32_t MD5::S32 = 11;
const uint32_t MD5::S33 = 16;
const uint32_t MD5::S34 = 23;
const uint32_t MD5::S41 = 6;
const uint32_t MD5::S42 = 10;
const uint32_t MD5::S43 = 15;
const uint32_t MD5::S44 = 21;

inline uint32_t MD5::F(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
inline uint32_t MD5::G(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); }
inline uint32_t MD5::H(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
inline uint32_t MD5::I(uint32_t x, uint32_t y, uint32_t z) { return y ^ (x | ~z); }
inline uint32_t MD5::rotate_left(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
inline void MD5::FF(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac) {
    a += F(b, c, d) + x + ac;
    a = rotate_left(a, s);
    a += b;
}
inline void MD5::GG(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac) {
    a += G(b, c, d) + x + ac;
    a = rotate_left(a, s);
    a += b;
}
inline void MD5::HH(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac) {
    a += H(b, c, d) + x + ac;
    a = rotate_left(a, s);
    a += b;
}
inline void MD5::II(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac) {
    a += I(b, c, d) + x + ac;
    a = rotate_left(a, s);
    a += b;
}

MD5::MD5() {
    finalized = false;
    count[0] = count[1] = 0;
    state[0] = 0x67452301;
    state[1] = 0xefcdab89;
    state[2] = 0x98badcfe;
    state[3] = 0x10325476;
}

void MD5::update(const unsigned char* data, size_t length) {
    size_t i, index, part_len;

    index = (count[0] >> 3) & 0x3F;

    if ((count[0] += static_cast<uint32_t>(length << 3)) < (length << 3))
        count[1]++;
    count[1] += static_cast<uint32_t>(length >> 29);

    part_len = 64 - index;

    if (length >= part_len) {
        memcpy(&buffer[index], data, part_len);
        transform(buffer);

        for (i = part_len; i + 63 < length; i += 64)
            transform(&data[i]);

        index = 0;
    } else {
        i = 0;
    }

    memcpy(&buffer[index], &data[i], length - i);
}

void MD5::update(const char* data, size_t length) {
    update(reinterpret_cast<const unsigned char*>(data), length);
}

MD5& MD5::finalize() {
    unsigned char bits[8];
    size_t index, pad_len;

    if (finalized) {
        return *this;
    }

    encode(bits, count, 8);

    index = (count[0] >> 3) & 0x3f;
    pad_len = (index < 56) ? (56 - index) : (120 - index);
    update(PADDING, pad_len);

    update(bits, 8);

    encode(digest, state, 16);

    memset(buffer, 0, sizeof buffer);
    memset(count, 0, sizeof count);

    finalized = true;

    return *this;
}

void MD5::transform(const unsigned char block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];

    decode(x, block, 64);

    FF(a, b, c, d, x[0], S11, 0xd76aa478);
    FF(d, a, b, c, x[1], S12, 0xe8c7b756);
    FF(c, d, a, b, x[2], S13, 0x242070db);
    FF(b, c, d, a, x[3], S14, 0xc1bdceee);
    FF(a, b, c, d, x[4], S11, 0xf57c0faf);
    FF(d, a, b, c, x[5], S12, 0x4787c62a);
    FF(c, d, a, b, x[6], S13, 0xa8304613);
    FF(b, c, d, a, x[7], S14, 0xfd469501);
    FF(a, b, c, d, x[8], S11, 0x698098d8);
    FF(d, a, b, c, x[9], S12, 0x8b44f7af);
    FF(c, d, a, b, x[10], S13, 0xffff5bb1);
    FF(b, c, d, a, x[11], S14, 0x895cd7be);
    FF(a, b, c, d, x[12], S11, 0x6b901122);
    FF(d, a, b, c, x[13], S12, 0xfd987193);
    FF(c, d, a, b, x[14], S13, 0xa679438e);
    FF(b, c, d, a, x[15], S14, 0x49b40821);

    GG(a, b, c, d, x[1], S21, 0xf61e2562);
    GG(d, a, b, c, x[6], S22, 0xc040b340);
    GG(c, d, a, b, x[11], S23, 0x265e5a51);
    GG(b, c, d, a, x[0], S24, 0xe9b6c7aa);
    GG(a, b, c, d, x[5], S21, 0xd62f105d);
    GG(d, a, b, c, x[10], S22, 0x02441453);
    GG(c, d, a, b, x[15], S23, 0xd8a1e681);
    GG(b, c, d, a, x[4], S24, 0xe7d3fbc8);
    GG(a, b, c, d, x[9], S21, 0x21e1cde6);
    GG(d, a, b, c, x[14], S22, 0xc33707d6);
    GG(c, d, a, b, x[3], S23, 0xf4d50d87);
    GG(b, c, d, a, x[8], S24, 0x455a14ed);
    GG(a, b, c, d, x[13], S21, 0xa9e3e905);
    GG(d, a, b, c, x[2], S22, 0xfcefa3f8);
    GG(c, d, a, b, x[7], S23, 0x676f02d9);
    GG(b, c, d, a, x[12], S24, 0x8d2a4c8a);

    HH(a, b, c, d, x[5], S31, 0xfffa3942);
    HH(d, a, b, c, x[8], S32, 0x8771f681);
    HH(c, d, a, b, x[11], S33, 0x6d9d6122);
    HH(b, c, d, a, x[14], S34, 0xfde5380c);
    HH(a, b, c, d, x[1], S31, 0xa4beea44);
    HH(d, a, b, c, x[4], S32, 0x4bdecfa9);
    HH(c, d, a, b, x[7], S33, 0xf6bb4b60);
    HH(b, c, d, a, x[10], S34, 0xbebfbc70);
    HH(a, b, c, d, x[13], S31, 0x289b7ec6);
    HH(d, a, b, c, x[0], S32, 0xeaa127fa);
    HH(c, d, a, b, x[3], S33, 0xd4ef3085);
    HH(b, c, d, a, x[6], S34, 0x04881d05);
    HH(a, b, c, d, x[9], S31, 0xd9d4d039);
    HH(d, a, b, c, x[12], S32, 0xe6db99e5);
    HH(c, d, a, b, x[15], S33, 0x1fa27cf8);
    HH(b, c, d, a, x[2], S34, 0xc4ac5665);

    II(a, b, c, d, x[0], S41, 0xf4292244);
    II(d, a, b, c, x[7], S42, 0x432aff97);
    II(c, d, a, b, x[14], S43, 0xab9423a7);
    II(b, c, d, a, x[5], S44, 0xfc93a039);
    II(a, b, c, d, x[12], S41, 0x655b59c3);
    II(d, a, b, c, x[3], S42, 0x8f0ccc92);
    II(c, d, a, b, x[10], S43, 0xffeff47d);
    II(b, c, d, a, x[1], S44, 0x85845dd1);
    II(a, b, c, d, x[8], S41, 0x6fa87e4f);
    II(d, a, b, c, x[15], S42, 0xfe2ce6e0);
    II(c, d, a, b, x[6], S43, 0xa3014314);
    II(b, c, d, a, x[13], S44, 0x4e0811a1);
    II(a, b, c, d, x[4], S41, 0xf7537e82);
    II(d, a, b, c, x[11], S42, 0xbd3af235);
    II(c, d, a, b, x[2], S43, 0x2ad7d2bb);
    II(b, c, d, a, x[9], S44, 0xeb86d391);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;

    memset(x, 0, sizeof x);
}

void MD5::decode(uint32_t output[], const unsigned char input[], size_t len) {
    for (size_t i = 0, j = 0; j < len; i++, j += 4)
        output[i] = ((uint32_t)input[j]) | (((uint32_t)input[j + 1]) << 8) |
            (((uint32_t)input[j + 2]) << 16) | (((uint32_t)input[j + 3]) << 24);
}

void MD5::encode(unsigned char output[], const uint32_t input[], size_t len) {
    for (size_t i = 0, j = 0; j < len; i++, j += 4) {
        output[j] = input[i] & 0xff;
        output[j + 1] = (input[i] >> 8) & 0xff;
        output[j + 2] = (input[i] >> 16) & 0xff;
        output[j + 3] = (input[i] >> 24) & 0xff;
    }
}

std::string MD5::hexdigest() const {
    if (!finalized) {
        return "";
    }

    std::ostringstream result;
    for (int i = 0; i < 16; i++) {
        result << HEX[(digest[i] >> 4) & 0x0f] << HEX[digest[i] & 0x0f];
    }

    return result.str();
}
