#ifndef SAES_H
#define SAES_H

#include <string>
#include <vector>
#include <array>

using namespace std;

class SAES {
public:
    // S-Box pra SubNibbles
    static const array<uint8_t, 16> SBOX;
    static const array<uint8_t, 16> INVERSE_SBOX;

private:
    // expansao Key
    vector<array<array<uint8_t, 2>, 2>> roundKeys;
    
    // helpers
    array<array<uint8_t, 2>, 2> stringToBlock(const string& input);
    string blockToString(const array<array<uint8_t, 2>, 2>& block);
    array<array<uint8_t, 2>, 2> addRoundKey(const array<array<uint8_t, 2>, 2>& state, 
                                            const array<array<uint8_t, 2>, 2>& key);
    array<array<uint8_t, 2>, 2> subNibbles(const array<array<uint8_t, 2>, 2>& state, bool inverse = false);
    array<array<uint8_t, 2>, 2> shiftRows(const array<array<uint8_t, 2>, 2>& state);
    array<array<uint8_t, 2>, 2> mixColumns(const array<array<uint8_t, 2>, 2>& state);
    array<array<uint8_t, 2>, 2> inverseMixColumns(const array<array<uint8_t, 2>, 2>& state);
    uint8_t multiplyGF24(uint8_t a, uint8_t b);
    void keyExpansion(const array<array<uint8_t, 2>, 2>& key);

    // helper pra ECB mode
    vector<string> splitIntoBlocks(const string& input);
    string padBlock(const string& block);

public:
    SAES(const string& key);
    string encrypt(const string& plaintext);
    string decrypt(const string& ciphertext);
    string toHex(const string& input);
    string toBase64(const string& input);
    
    // funcoes do modo ECB
    string encryptECB(const string& plaintext);
    string decryptECB(const string& ciphertext);
};

#endif // SAES_H
