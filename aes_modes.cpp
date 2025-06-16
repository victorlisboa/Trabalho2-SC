#include "aes_modes.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cmath>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

AESModes::AESModes() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    
    // Generate random key and IV
    generate_random_bytes(key, KEY_SIZE);
    generate_random_bytes(iv, IV_SIZE);
}

AESModes::~AESModes() {
    // Clean up OpenSSL
    EVP_cleanup();
}

void AESModes::generate_random_bytes(unsigned char* buffer, int size) {
    if (RAND_bytes(buffer, size) != 1) {
        throw std::runtime_error("Failed to generate random bytes");
    }
}

std::string AESModes::base64_encode(const unsigned char* input, int length) {
    BIO *bmem, *b64;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    std::string result(bptr->data, bptr->length - 1);
    BIO_free_all(b64);

    return result;
}

std::string AESModes::base64_decode(const std::string& input) {
    BIO *b64, *bmem;
    size_t length = input.length();
    unsigned char* buffer = new unsigned char[length];
    memset(buffer, 0, length);

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new_mem_buf(input.c_str(), input.length());
    bmem = BIO_push(b64, bmem);

    BIO_read(bmem, buffer, input.length());
    BIO_free_all(bmem);

    std::string result(reinterpret_cast<char*>(buffer), length);
    delete[] buffer;
    return result;
}

double AESModes::calculate_entropy(const std::string& data) {
    int freq[256] = {0};
    for (unsigned char c : data) {
        freq[c]++;
    }

    double entropy = 0.0;
    double size = data.length();
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = freq[i] / size;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

std::string AESModes::encrypt_aes(const std::string& plaintext, const EVP_CIPHER* cipher) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }

    int len;
    int ciphertext_len;
    std::vector<unsigned char> ciphertext(plaintext.length() + EVP_MAX_BLOCK_LENGTH);

    // Initialize encryption
    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encryption");
    }

    // Perform encryption
    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, 
                              reinterpret_cast<const unsigned char*>(plaintext.c_str()), 
                              plaintext.length())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to encrypt data");
    }
    ciphertext_len = len;

    // Finalize encryption
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize encryption");
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return std::string(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len);
}

std::string AESModes::decrypt_aes(const std::string& ciphertext, const EVP_CIPHER* cipher) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }

    int len;
    int plaintext_len;
    std::vector<unsigned char> plaintext(ciphertext.length());

    // Initialize decryption
    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize decryption");
    }

    // Perform decryption
    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                              reinterpret_cast<const unsigned char*>(ciphertext.c_str()),
                              ciphertext.length())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to decrypt data");
    }
    plaintext_len = len;

    // Finalize decryption
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize decryption");
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
}

// Encryption modes
std::string AESModes::encrypt_ecb(const std::string& plaintext) {
    return encrypt_aes(plaintext, EVP_aes_256_ecb());
}

std::string AESModes::encrypt_cbc(const std::string& plaintext) {
    return encrypt_aes(plaintext, EVP_aes_256_cbc());
}

std::string AESModes::encrypt_cfb(const std::string& plaintext) {
    return encrypt_aes(plaintext, EVP_aes_256_cfb());
}

std::string AESModes::encrypt_ofb(const std::string& plaintext) {
    return encrypt_aes(plaintext, EVP_aes_256_ofb());
}

std::string AESModes::encrypt_ctr(const std::string& plaintext) {
    return encrypt_aes(plaintext, EVP_aes_256_ctr());
}

// Decryption modes
std::string AESModes::decrypt_ecb(const std::string& ciphertext) {
    return decrypt_aes(ciphertext, EVP_aes_256_ecb());
}

std::string AESModes::decrypt_cbc(const std::string& ciphertext) {
    return decrypt_aes(ciphertext, EVP_aes_256_cbc());
}

std::string AESModes::decrypt_cfb(const std::string& ciphertext) {
    return decrypt_aes(ciphertext, EVP_aes_256_cfb());
}

std::string AESModes::decrypt_ofb(const std::string& ciphertext) {
    return decrypt_aes(ciphertext, EVP_aes_256_ofb());
}

std::string AESModes::decrypt_ctr(const std::string& ciphertext) {
    return decrypt_aes(ciphertext, EVP_aes_256_ctr());
}

double AESModes::measure_entropy(const std::string& data) {
    return calculate_entropy(data);
}

void AESModes::print_analysis(const std::string& mode, const std::string& plaintext,
                            const std::string& ciphertext, double time_ms) {
    std::cout << "\nMode: " << mode << std::endl;
    std::cout << "Plaintext length: " << plaintext.length() << " bytes" << std::endl;
    std::cout << "Ciphertext length: " << ciphertext.length() << " bytes" << std::endl;
    std::cout << "Encryption time: " << time_ms << " ms" << std::endl;
    std::cout << "Plaintext entropy: " << measure_entropy(plaintext) << " bits" << std::endl;
    std::cout << "Ciphertext entropy: " << measure_entropy(ciphertext) << " bits" << std::endl;
    std::cout << "Ciphertext (base64): " << base64_encode(
        reinterpret_cast<const unsigned char*>(ciphertext.c_str()),
        ciphertext.length()) << std::endl;
} 