#ifndef AES_MODES_H
#define AES_MODES_H

#include <string>
#include <vector>
#include <chrono>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

class AESModes {
private:
    // Key and IV sizes
    static const int KEY_SIZE = 32;  // 256 bits
    static const int IV_SIZE = 16;   // 128 bits
    static const int BLOCK_SIZE = 16; // 128 bits

    // Key and IV
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];

    // Helper functions
    std::string base64_encode(const unsigned char* input, int length);
    std::string base64_decode(const std::string& input);
    void generate_random_bytes(unsigned char* buffer, int size);
    double calculate_entropy(const std::string& data);
    std::string encrypt_aes(const std::string& plaintext, const EVP_CIPHER* cipher);
    std::string decrypt_aes(const std::string& ciphertext, const EVP_CIPHER* cipher);

public:
    AESModes();
    ~AESModes();

    // Encryption modes
    std::string encrypt_ecb(const std::string& plaintext);
    std::string encrypt_cbc(const std::string& plaintext);
    std::string encrypt_cfb(const std::string& plaintext);
    std::string encrypt_ofb(const std::string& plaintext);
    std::string encrypt_ctr(const std::string& plaintext);

    // Decryption modes
    std::string decrypt_ecb(const std::string& ciphertext);
    std::string decrypt_cbc(const std::string& ciphertext);
    std::string decrypt_cfb(const std::string& ciphertext);
    std::string decrypt_ofb(const std::string& ciphertext);
    std::string decrypt_ctr(const std::string& ciphertext);

    // Analysis functions
    double measure_entropy(const std::string& data);
    void print_analysis(const std::string& mode, const std::string& plaintext, 
                       const std::string& ciphertext, double time_ms);
};

#endif // AES_MODES_H 