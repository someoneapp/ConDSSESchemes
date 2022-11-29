#ifndef CRYPTO_UTIL_H
#define CRYPTO_UTIL_H

//#include <random>

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <vector>
//#include <fstream>
//#include <cassert>
//#include <memory>
#include <string>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <set>
#include <map>
#include <vector>
//#include <stdexcept>
//#include <csignal>
//#include <unordered_set>
//#include <unistd.h>

//#include <sys/time.h>

#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
//#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/integer.h>

#include <time.h>
#include <sys/time.h>

#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>
//#include "aes/aes_ctr.h"
#define AES128_KEY_LEN 16
typedef struct { __m128i rd_key[7+AES128_KEY_LEN/4]; } AES_KEY;
#define ROUNDS(ctx) (6+AES128_KEY_LEN/4)


namespace STORAGE {

    class Cutil {

    public:
        static std::string F(const std::string token, const CryptoPP::byte *key);
        static std::string Xor(const std::string s1, const std::string s2);
        static std::string H1(const std::string message);
        static std::string H2(const std::string message);
        static double getCurrentTime();
        static std::string CTR_AESEncryptStr(const CryptoPP::byte *skey, const CryptoPP::byte *siv, const std::string plainText);
        static int AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
        //static std::string F_aesni(AES_KEY    *key, const void *e, int e_len);
        static std::string F_aesni(AES_KEY    *key, const void *e, int e_len, int option);
        static void F_p(const std::string s, AES_KEY *key, const CryptoPP::Integer& p, CryptoPP::Integer& res);
        static std::string Inttostring(const CryptoPP::Integer& a);
        static std::string bittohex(std::string bs);
        static std::string henc(const CryptoPP::Integer& skey, const CryptoPP::Integer& m, const CryptoPP::Integer& n);
        static void Bytestoint(const std::string s, CryptoPP::Integer& res);
    };

}// namespace SSE

#endif //SSE_UTIL_H