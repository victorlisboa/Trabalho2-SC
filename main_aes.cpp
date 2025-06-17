#include "aes_modes.h"
#include <iostream>
#include <chrono>
#include <iomanip>

using namespace std;

void test_mode(AESModes& aes, const string& mode_name, 
               string (AESModes::*encrypt_func)(const string&),
               string (AESModes::*decrypt_func)(const string&),
               const string& plaintext) {
    cout << "\n=== Testando modo " << mode_name << " ===\n";
    
    // mede tempo de criptografia
    auto start = chrono::high_resolution_clock::now();
    string ciphertext = (aes.*encrypt_func)(plaintext);
    auto end = chrono::high_resolution_clock::now();
    double time_ms = chrono::duration<double, milli>(end - start).count();
    
    // printa analise
    aes.print_analysis(mode_name, plaintext, ciphertext, time_ms);
    
    // descriptografa e verifica
    string decrypted = (aes.*decrypt_func)(ciphertext);
    cout << "texto descriptografado: " << decrypted << '\n';
    cout << "descriptografia concluida com sucesso: " << (decrypted == plaintext ? "sim" : "nao") << '\n';
}

int main() {
    try {
        AESModes aes;
        
        // mensagem de teste
        string plaintext = "Essa eh uma mensagem de teste para a criptografia AES. "
                               "Ela contem multiplos blocos para representar"
                               " modos de operacao diferentes.";
        
        // testa todos os modos
        test_mode(aes, "ECB", &AESModes::encrypt_ecb, &AESModes::decrypt_ecb, plaintext);
        test_mode(aes, "CBC", &AESModes::encrypt_cbc, &AESModes::decrypt_cbc, plaintext);
        test_mode(aes, "CFB", &AESModes::encrypt_cfb, &AESModes::decrypt_cfb, plaintext);
        test_mode(aes, "OFB", &AESModes::encrypt_ofb, &AESModes::decrypt_ofb, plaintext);
        test_mode(aes, "CTR", &AESModes::encrypt_ctr, &AESModes::decrypt_ctr, plaintext);
        
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << '\n';
        return 1;
    }
    
    return 0;
} 