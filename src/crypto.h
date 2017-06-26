#pragma once

#include <string>

namespace RethinkDB {
    
    class Crypto{
        
        
    public:
        static int32_t base64(const unsigned char *input, int32_t length, char* output);
        static std::string base64String(const unsigned char *input, int32_t length);
        static int32_t unbase64(const char *input, int32_t length, unsigned char* output);
        static int32_t sha256(const unsigned char* data, int32_t length, unsigned char* output);
        static int32_t hmac_sha256(const unsigned char* key, int32_t keyLenght, const unsigned char* data, int32_t lenght, unsigned char* output);
        static int32_t pbkdf2(const char* pass, const unsigned char* salt, int32_t saltLenght, int32_t iterations, unsigned char* output);
        static int32_t make_nonce(char* output, int32_t size);
        static int32_t x_or(const unsigned char* a, int32_t alenght, const unsigned char* b, int32_t blenght, unsigned char* output);
    };
    
}
