#include "saes.h"
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <iostream>

using namespace std;

// S-Box
const array<uint8_t, 16> SAES::SBOX = {
    0x9, 0x4, 0xA, 0xB,
    0xD, 0x1, 0x8, 0x5,
    0x6, 0x2, 0x0, 0x3,
    0xC, 0xE, 0xF, 0x7
};

// inverse S-Box
const array<uint8_t, 16> SAES::INVERSE_SBOX = {
    0xA, 0x5, 0x9, 0xB,
    0x1, 0x7, 0x8, 0xF,
    0x6, 0x0, 0x2, 0x3,
    0xC, 0x4, 0xD, 0xE
};

SAES::SAES(const string& key) {
    // converte key para um bloco 2x2
    array<array<uint8_t, 2>, 2> keyBlock = stringToBlock(key);
    keyExpansion(keyBlock);
}

array<array<uint8_t, 2>, 2> SAES::stringToBlock(const string& input) {
    array<array<uint8_t, 2>, 2> block = {{{0, 0}, {0, 0}}};
    
    if (input.length() >= 2) {
        // primeiro byte
        block[0][0] = (input[0] >> 4) & 0x0F;  // high nibble
        block[1][0] = input[0] & 0x0F;         // low nibble
        
        // segundo byte
        block[0][1] = (input[1] >> 4) & 0x0F;  // high nibble
        block[1][1] = input[1] & 0x0F;         // low nibble
    }
    
    return block;
}

string SAES::blockToString(const array<array<uint8_t, 2>, 2>& block) {
    string result;
    
    // primeiro byte
    char byte1 = ((block[0][0] & 0x0F) << 4) | (block[1][0] & 0x0F);
    result += byte1;
    
    // segundo byte
    char byte2 = ((block[0][1] & 0x0F) << 4) | (block[1][1] & 0x0F);
    result += byte2;
    
    return result;
}

array<array<uint8_t, 2>, 2> SAES::addRoundKey(
    const array<array<uint8_t, 2>, 2>& state,
    const array<array<uint8_t, 2>, 2>& key) {
    
    array<array<uint8_t, 2>, 2> result;
    for (int i = 0; i < 2; ++i) {
        for (int j = 0; j < 2; ++j) {
            result[i][j] = state[i][j] ^ key[i][j];
        }
    }
    return result;
}

array<array<uint8_t, 2>, 2> SAES::subNibbles(
    const array<array<uint8_t, 2>, 2>& state,
    bool inverse) {
    
    array<array<uint8_t, 2>, 2> result;
    const auto& sbox = inverse ? INVERSE_SBOX : SBOX;
    
    for (int i = 0; i < 2; ++i) {
        for (int j = 0; j < 2; ++j) {
            result[i][j] = sbox[state[i][j]];
        }
    }
    return result;
}

array<array<uint8_t, 2>, 2> SAES::shiftRows(
    const array<array<uint8_t, 2>, 2>& state) {
    
    array<array<uint8_t, 2>, 2> result = state;
    // Shift segunda linha em uma posicao
    swap(result[1][0], result[1][1]);
    return result;
}

uint8_t SAES::multiplyGF24(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    while (b > 0) {
        if (b & 1) {
            result ^= a;
        }
        if (a & 0x8) {
            a = (a << 1) ^ 0x13; // x^4 + x + 1
        } else {
            a <<= 1;
        }
        b >>= 1;
    }
    return result & 0x0F;
}

array<array<uint8_t, 2>, 2> SAES::mixColumns(
    const array<array<uint8_t, 2>, 2>& state) {
    
    array<array<uint8_t, 2>, 2> result;
    for (int i = 0; i < 2; ++i) {
        result[0][i] = multiplyGF24(0x1, state[0][i]) ^ multiplyGF24(0x4, state[1][i]);
        result[1][i] = multiplyGF24(0x4, state[0][i]) ^ multiplyGF24(0x1, state[1][i]);
    }
    return result;
}

array<array<uint8_t, 2>, 2> SAES::inverseMixColumns(const array<array<uint8_t, 2>, 2>& state) {
    array<array<uint8_t, 2>, 2> result;
    // matriz inversa => [[9, 2], [2, 9]] em GF(2^4)
    for (int i = 0; i < 2; ++i) {
        result[0][i] = multiplyGF24(0x9, state[0][i]) ^ multiplyGF24(0x2, state[1][i]);
        result[1][i] = multiplyGF24(0x2, state[0][i]) ^ multiplyGF24(0x9, state[1][i]);
    }
    return result;
}

// helper: faz swap dos nibbles de um byte
static uint8_t RotNib(uint8_t b) {
    return ((b & 0x0F) << 4) | ((b & 0xF0) >> 4);
}

// helper: aplica S-Box pra cada nibble de um byte
static uint8_t SubNib(uint8_t b) {
    return (SAES::SBOX[(b >> 4) & 0x0F] << 4) | SAES::SBOX[b & 0x0F];
}

void SAES::keyExpansion(const array<array<uint8_t, 2>, 2>& key) {
    roundKeys.clear();
    // converte nibbles em 2x2 em 2 bytes (w0, w1)
    uint8_t w0 = ((key[0][0] & 0x0F) << 4) | (key[1][0] & 0x0F);
    uint8_t w1 = ((key[0][1] & 0x0F) << 4) | (key[1][1] & 0x0F);
    
    // expansao da key
    uint8_t w2 = w0 ^ 0x80 ^ SubNib(RotNib(w1));
    uint8_t w3 = w2 ^ w1;
    uint8_t w4 = w2 ^ 0x30 ^ SubNib(RotNib(w3));
    uint8_t w5 = w4 ^ w3;
    
    // transforma keys em nibbles 2x2
    auto toBlock = [](uint8_t a, uint8_t b) {
        array<array<uint8_t, 2>, 2> block;
        block[0][0] = (a >> 4) & 0x0F;
        block[1][0] = a & 0x0F;
        block[0][1] = (b >> 4) & 0x0F;
        block[1][1] = b & 0x0F;
        return block;
    };
    roundKeys.push_back(toBlock(w0, w1));
    roundKeys.push_back(toBlock(w2, w3));
    roundKeys.push_back(toBlock(w4, w5));
}

void SAES::printState(const array<array<uint8_t, 2>, 2>& state, const string& label) {
    cout << "\n" << label << ":" << endl;
    cout << hex << setfill('0');
    for (int i = 0; i < 2; ++i) {
        for (int j = 0; j < 2; ++j) {
            cout << setw(2) << static_cast<int>(state[i][j]) << " ";
        }
        cout << endl;
    }
    cout << dec;
}

string SAES::encrypt(const string& plaintext) {
    array<array<uint8_t, 2>, 2> state = stringToBlock(plaintext);
    
    cout << "\nEstado inicial:" << endl;
    printState(state, "Estado inicial");
    
    // round 0
    state = addRoundKey(state, roundKeys[0]);
    printState(state, "Após AddRoundKey (Round 0)");
    
    // round 1
    state = subNibbles(state);
    printState(state, "Após SubNibbles (Round 1)");
    state = shiftRows(state);
    printState(state, "Após ShiftRows (Round 1)");
    state = mixColumns(state);
    printState(state, "Após MixColumns (Round 1)");
    state = addRoundKey(state, roundKeys[1]);
    printState(state, "Após AddRoundKey (Round 1)");
    
    // round 2
    state = subNibbles(state);
    printState(state, "Após SubNibbles (Round 2)");
    state = shiftRows(state);
    printState(state, "Após ShiftRows (Round 2)");
    state = addRoundKey(state, roundKeys[2]);
    printState(state, "Após AddRoundKey (Round 2)");
    
    return blockToString(state);
}

string SAES::decrypt(const string& ciphertext) {
    array<array<uint8_t, 2>, 2> state = stringToBlock(ciphertext);
    
    // round 2
    state = addRoundKey(state, roundKeys[2]);
    state = shiftRows(state);
    state = subNibbles(state, true);
    
    // round 1
    state = addRoundKey(state, roundKeys[1]);
    state = inverseMixColumns(state);
    state = shiftRows(state);
    state = subNibbles(state, true);
    
    // round 0
    state = addRoundKey(state, roundKeys[0]);
    
    return blockToString(state);
}

string SAES::toHex(const string& input) {
    stringstream ss;
    for (unsigned char c : input) {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(c);
    }
    return ss.str();
}

string SAES::toBase64(const string& input) {
    // converte a mensagem para base 64
    const string base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    
    for (unsigned char c : input) {
        char_array_3[i++] = c;
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            
            for (i = 0; i < 4; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }
    
    if (i) {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';
            
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;
        
        for (j = 0; j < i + 1; j++)
            ret += base64_chars[char_array_4[j]];
            
        while ((i++ < 3))
            ret += '=';
    }
    
    return ret;
}

vector<string> SAES::splitIntoBlocks(const string& input) {
    vector<string> blocks;
    for (size_t i = 0; i < input.length(); i += 2) {
        string block = input.substr(i, 2);
        if (block.length() < 2) {
            block = padBlock(block);
        }
        blocks.push_back(block);
    }
    return blocks;
}

string SAES::padBlock(const string& block) {
    if (block.length() == 2) return block;
    string padded = block;
    padded += '\0';  // PKCS#7 padding
    return padded;
}

string SAES::encryptECB(const string& plaintext) {
    vector<string> blocks = splitIntoBlocks(plaintext);
    string result;
    
    for (const auto& block : blocks) {
        result += encrypt(block);
    }
    
    return result;
}

string SAES::decryptECB(const string& ciphertext) {
    vector<string> blocks = splitIntoBlocks(ciphertext);
    string result;
    
    for (const auto& block : blocks) {
        result += decrypt(block);
    }
    
    return result;
}
