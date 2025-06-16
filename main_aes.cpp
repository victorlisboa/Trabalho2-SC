#include "aes_modes.h"
#include <iostream>
#include <chrono>
#include <iomanip>

using namespace std;

void test_mode(AESModes& aes, const string& mode_name, 
               string (AESModes::*encrypt_func)(const string&),
               string (AESModes::*decrypt_func)(const string&),
               const string& plaintext) {
    cout << "\n=== Testing " << mode_name << " Mode ===" << endl;
    
    // Measure encryption time
    auto start = chrono::high_resolution_clock::now();
    string ciphertext = (aes.*encrypt_func)(plaintext);
    auto end = chrono::high_resolution_clock::now();
    double time_ms = chrono::duration<double, milli>(end - start).count();
    
    // Print analysis
    aes.print_analysis(mode_name, plaintext, ciphertext, time_ms);
    
    // Decrypt and verify
    string decrypted = (aes.*decrypt_func)(ciphertext);
    cout << "Decrypted text: " << decrypted << endl;
    cout << "Decryption successful: " << (decrypted == plaintext ? "Yes" : "No") << endl;
}

int main() {
    try {
        AESModes aes;
        
        // Test message
        string plaintext = "This is a test message for AES encryption. "
                               "It contains multiple blocks to demonstrate "
                               "different modes of operation.";
        
        // Test all modes
        test_mode(aes, "ECB", &AESModes::encrypt_ecb, &AESModes::decrypt_ecb, plaintext);
        test_mode(aes, "CBC", &AESModes::encrypt_cbc, &AESModes::decrypt_cbc, plaintext);
        test_mode(aes, "CFB", &AESModes::encrypt_cfb, &AESModes::decrypt_cfb, plaintext);
        test_mode(aes, "OFB", &AESModes::encrypt_ofb, &AESModes::decrypt_ofb, plaintext);
        test_mode(aes, "CTR", &AESModes::encrypt_ctr, &AESModes::decrypt_ctr, plaintext);
        
        // Demonstrate ECB weakness with identical blocks
        cout << "\n=== Demonstrating ECB Weakness ===" << endl;
        string repeated = "AAAA";  // Two identical blocks
        test_mode(aes, "ECB (Repeated Blocks)", &AESModes::encrypt_ecb, &AESModes::decrypt_ecb, repeated);
        
        // Test with a different message to show pattern differences
        string pattern = "ABABABAB";  // Alternating pattern
        test_mode(aes, "ECB (Pattern)", &AESModes::encrypt_ecb, &AESModes::decrypt_ecb, pattern);
        
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    
    return 0;
} 