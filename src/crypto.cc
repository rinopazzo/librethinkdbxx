//
//  crypto.cpp
//  DTFramework
//
//  Created by Rino Seminara on 30/05/17.
//  Copyright © 2017 A-Tono. All rights reserved.
//

#include "crypto.h"
#include <openssl/rsa.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <string.h>

#ifdef WINRT
#define strdup _strdup
#endif

using namespace RethinkDB;

int32_t Crypto::base64(const unsigned char *input, int32_t length, char* output){
    BIO *bmem, *b64;
    BUF_MEM *bptr;
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    memcpy(output, bptr->data, bptr->length);
    output[bptr->length] = 0;
    BIO_free_all(b64);
    
    return (int32_t)bptr->length;
}

std::string Crypto::base64String(const unsigned char *input, int32_t length){
    char* output = (char*)malloc(1024 * sizeof(char));
    memset(output, 0, 1024);
    Crypto::base64(input, length, output);
    return std::string(output);
}

int32_t Crypto::unbase64(const char *input, int32_t length, unsigned char* output){
    BIO *b64, *bmem;
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf(input, length);
    bmem = BIO_push(b64, bmem);
    int32_t resultLen= BIO_read(bmem, output, length);
    BIO_free_all(bmem);
    return resultLen;
}

int32_t Crypto::sha256(const unsigned char* data, int32_t lenght, unsigned char* output){
    //SHA256(reinterpret_cast<const unsigned char*>(data), 0, output);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, lenght);
    SHA256_Final(output, &sha256);
    return SHA256_DIGEST_LENGTH;
}

int32_t Crypto::hmac_sha256(const unsigned char* key, int32_t keyLenght, const unsigned char* data, int32_t lenght, unsigned char* output){
    unsigned int result_len;
    unsigned char result[EVP_MAX_MD_SIZE];
    
    HMAC(EVP_sha256(),
         key, keyLenght,
         data, lenght,
         result, &result_len);
    memcpy(output, result, result_len);
    
    return result_len;
}

int32_t Crypto::pbkdf2(const char* pass, const unsigned char* salt, int32_t saltLenght, int32_t iterations, unsigned char* output)
{
    //unsigned int i;
    int result = PKCS5_PBKDF2_HMAC(pass, -1, salt, saltLenght, iterations, EVP_sha256(), 256, output);
    //for (i = 0; i < sizeof(digest); i++)
    //    sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]);
    
    return result?32:0;
}

int32_t Crypto::make_nonce(char* output, int32_t size){
    unsigned char* bytes = (unsigned char*)malloc(size * sizeof(unsigned char));
    memset(bytes, 0, size);
    int success = RAND_bytes(bytes, size);
    if(success==1){
        return base64(bytes, size, output);
    }
    return 0;
}

int32_t Crypto::x_or(const unsigned char* a, int32_t alenght, const unsigned char* b, int32_t blenght, unsigned char* output){
    if (alenght != blenght) {
        return 0;
    }
    for (int i = 0; i < alenght; i++) {
        output[i] = (a[i] ^ b[i]);
    }
    
    return alenght;
}


