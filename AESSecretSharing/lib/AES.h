
#ifndef AES_AES_H
#define AES_AES_H

#include <cstdint>
#include "GF256.h"

class AES
{
private:
    static const GF256 C[4][4];
    static const GF256 InvC[4][4];
    static const GF256 Rcon[16];
    GF256 key[32];
    GF256 state[4][4];
    GF256 w[15][4][4];
    void SubBytes();
    void InvSubBytes();
    void ShiftRows();
    void InvShiftRows();
    void MixColumns();
    void InvMixColumns();
    void AddRoundKey(int round);
    void KeyExpansion();
    static void RotWord(GF256 temp[4]);
    static void SubWord(GF256 temp[4]);
public:
    explicit AES(uint8_t key[32]);
    std::string getKey();
    std::string getState();
    std::string getW();
    uint8_t * encrypt(uint8_t in[16]);
    uint8_t * decrypt(uint8_t out[16]);
};
#endif //AES_AES_H
