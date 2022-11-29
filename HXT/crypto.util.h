#ifndef CRYPTO_UTIL_H
#define CRYPTO_UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <set>
#include <map>
#include <vector>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/integer.h>
#include <cryptopp/base64.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>

#include <time.h>
#include <sys/time.h>

#define AES128_KEY_LEN 16
#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>
#define AES128_KEY_LEN 16
typedef struct { __m128i rd_key[7+AES128_KEY_LEN/4]; } AES_KEY;
#define ROUNDS(ctx) (6+AES128_KEY_LEN/4)



namespace HXT {

    class Cutil {

    

    public:
        static std::string Xor(const std::string s1, const std::string s2);
        static std::string H(const std::string message);
        static std::string CTR_AESEncryptStr(const CryptoPP::byte *skey, const CryptoPP::byte *siv, const std::string plainText);
        static std::string CTR_AESDecryptStr(const CryptoPP::byte *skey, const CryptoPP::byte *siv, const std::string cipherText);
        static void F_p(const std::string s, AES_KEY *key, const CryptoPP::Integer& p, CryptoPP::Integer& res);
        static std::string Inttostring(const CryptoPP::Integer& a);
        static void generate_salt(unsigned int k, std::vector<unsigned int>& salt);
        static unsigned int hash_bf(const unsigned char* begin, std::size_t remaining_length, unsigned int hash);
        static double getCurrentTime();
        static int AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
        static std::string F_aesni(AES_KEY    *key, const void *e, int e_len, int t);

    };

}

#endif