#include "saes.h"
#include <iostream>
#include <string>
#include <iomanip>

using namespace std;

void printBlockAnalysis(const string& text, const string& ciphertext, size_t blockSize = 2) {
    cout << "\nanalise do bloco:" << '\n';
    cout << "blocos de texto (hex): ";
    for (size_t i = 0; i < text.length(); i += blockSize) {
        string block = text.substr(i, blockSize);
        cout << hex << setfill('0');
        for (char c : block) {
            cout << setw(2) << static_cast<int>(static_cast<unsigned char>(c)) << " ";
        }
        cout << "| ";
    }
    cout << dec << '\n';

    cout << "blocos cifrados (hex): ";
    for (size_t i = 0; i < ciphertext.length(); i += blockSize) {
        string block = ciphertext.substr(i, blockSize);
        cout << hex << setfill('0');
        for (char c : block) {
            cout << setw(2) << static_cast<int>(static_cast<unsigned char>(c)) << " ";
        }
        cout << "| ";
    }
    cout << dec << '\n';
}

int main() {
    // key
    string key = "AB";  // key de 16 bits
    
    // cria instancia do SAES
    SAES saes(key);
    
    // teste 1: mensangem simples
    cout << "\nteste 1: mensagem simples" << '\n';
    string plaintext1 = "Hello World!";
    string ciphertext1 = saes.encryptECB(plaintext1);
    string decrypted1 = saes.decryptECB(ciphertext1);
    
    cout << "plaintext: " << plaintext1 << '\n';
    cout << "ciphertext (base64): " << saes.toBase64(ciphertext1) << '\n';
    cout << "decrypted text: " << decrypted1 << '\n';

    // mostra analise do bloco do teste 1
    printBlockAnalysis(plaintext1, ciphertext1);
    
    // teste 2: demonstra fraqueza do ECB com blocos iguais
    cout << "\nteste 2: demonstra fraqueza do ECB com blocos iguais\n";
    string plaintext2 = "AAAA";  // 2 blocos iguais
    string ciphertext2 = saes.encryptECB(plaintext2);
    string decrypted2 = saes.decryptECB(ciphertext2);
    
    cout << "plaintext: " << plaintext2 << '\n';
    cout << "ciphertext (base64): " << saes.toBase64(ciphertext2) << '\n';
    cout << "decrypted text: " << decrypted2 << '\n';
    
    // mostra analise do bloco do teste 2
    printBlockAnalysis(plaintext2, ciphertext2);
    
    // teste 3: repetindo padrao
    cout << "\nteste 3: repetindo padrao" << '\n';
    string plaintext3 = "ABABABAB";  // 4 blocos iguais
    string ciphertext3 = saes.encryptECB(plaintext3);
    string decrypted3 = saes.decryptECB(ciphertext3);
    
    cout << "plaintext: " << plaintext3 << '\n';
    cout << "ciphertext (base64): " << saes.toBase64(ciphertext3) << '\n';
    cout << "decrypted text: " << decrypted3 << '\n';
    
    // mostra analise do bloco do teste 3
    printBlockAnalysis(plaintext3, ciphertext3);
    
    return 0;
}
