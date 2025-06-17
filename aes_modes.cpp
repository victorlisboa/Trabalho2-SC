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

using namespace std;

AESModes::AESModes() {
    // inicializa OpenSSL
    OpenSSL_add_all_algorithms();
    
    // gera key e IV aleatorios
    generate_random_bytes(key, KEY_SIZE);
    generate_random_bytes(iv, IV_SIZE);
}

AESModes::~AESModes() {
    // Clean up OpenSSL
    EVP_cleanup();
}

void AESModes::generate_random_bytes(unsigned char* buffer, int size) {
    if (RAND_bytes(buffer, size) != 1) {
        throw runtime_error("Falha ao gerar bytes aleatorios");
    }
}

string AESModes::base64_encode(const unsigned char* input, int length) {
    BIO *bmem, *b64;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    string result(bptr->data, bptr->length - 1);
    BIO_free_all(b64);

    return result;
}

string AESModes::base64_decode(const string& input) {
    BIO *b64, *bmem;
    size_t length = input.length();
    unsigned char* buffer = new unsigned char[length];
    memset(buffer, 0, length);

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new_mem_buf(input.c_str(), input.length());
    bmem = BIO_push(b64, bmem);

    BIO_read(bmem, buffer, input.length());
    BIO_free_all(bmem);

    string result(reinterpret_cast<char*>(buffer), length);
    delete[] buffer;
    return result;
}

double AESModes::calculate_entropy(const string& data) {
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

string AESModes::encrypt_aes(const string& plaintext, const EVP_CIPHER* cipher) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw runtime_error("Falha ao criar contexto de criptografia");
    }

    int len;
    int ciphertext_len;
    vector<unsigned char> ciphertext(plaintext.length() + EVP_MAX_BLOCK_LENGTH);

    // inicializa criptografia
    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Falha ao inicializar criptografia");
    }

    // criptografa
    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, 
                              reinterpret_cast<const unsigned char*>(plaintext.c_str()), 
                              plaintext.length())) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Falha ao criptografar dados");
    }
    ciphertext_len = len;

    // finaliza criptografia
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Falha ao finalizar criptografia");
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return string(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len);
}

string AESModes::decrypt_aes(const string& ciphertext, const EVP_CIPHER* cipher) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw runtime_error("Falha ao criar contexto de descriptografia");
    }

    int len;
    int plaintext_len;
    vector<unsigned char> plaintext(ciphertext.length());

    // Initialize decryption
    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Falha ao inicializar descriptografia");
    }

    // Perform decryption
    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                              reinterpret_cast<const unsigned char*>(ciphertext.c_str()),
                              ciphertext.length())) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Falha ao descriptografar dados");
    }
    plaintext_len = len;

    // Finalize decryption
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Falha ao finalizar descriptografia");
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
}

// modos de criptografia
string AESModes::encrypt_ecb(const string& plaintext) {
    return encrypt_aes(plaintext, EVP_aes_256_ecb());
}

string AESModes::encrypt_cbc(const string& plaintext) {
    return encrypt_aes(plaintext, EVP_aes_256_cbc());
}

string AESModes::encrypt_cfb(const string& plaintext) {
    return encrypt_aes(plaintext, EVP_aes_256_cfb());
}

string AESModes::encrypt_ofb(const string& plaintext) {
    return encrypt_aes(plaintext, EVP_aes_256_ofb());
}

string AESModes::encrypt_ctr(const string& plaintext) {
    return encrypt_aes(plaintext, EVP_aes_256_ctr());
}

// modos de descriptografia
string AESModes::decrypt_ecb(const string& ciphertext) {
    return decrypt_aes(ciphertext, EVP_aes_256_ecb());
}

string AESModes::decrypt_cbc(const string& ciphertext) {
    return decrypt_aes(ciphertext, EVP_aes_256_cbc());
}

string AESModes::decrypt_cfb(const string& ciphertext) {
    return decrypt_aes(ciphertext, EVP_aes_256_cfb());
}

string AESModes::decrypt_ofb(const string& ciphertext) {
    return decrypt_aes(ciphertext, EVP_aes_256_ofb());
}

string AESModes::decrypt_ctr(const string& ciphertext) {
    return decrypt_aes(ciphertext, EVP_aes_256_ctr());
}

double AESModes::measure_entropy(const string& data) {
    return calculate_entropy(data);
}

void AESModes::print_analysis(const string& mode, const string& plaintext,
                            const string& ciphertext, double time_ms) {
    cout << "\nmodo: " << mode << endl;
    cout << "tamanho do plaintext: " << plaintext.length() << " bytes" << endl;
    cout << "tamanho do ciphertext: " << ciphertext.length() << " bytes" << endl;
    cout << "tempo de criptografia: " << time_ms << " ms" << endl;
    cout << "entropia do plaintext: " << measure_entropy(plaintext) << " bits" << endl;
    cout << "entropia do ciphertext: " << measure_entropy(ciphertext) << " bits" << endl;
    cout << "ciphertext (base64): " << base64_encode(
        reinterpret_cast<const unsigned char*>(ciphertext.c_str()),
        ciphertext.length()) << endl;
}
