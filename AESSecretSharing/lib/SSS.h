

#ifndef AESSECRETSHARING_SSS_H
#define AESSECRETSHARING_SSS_H

#include "../../AES/lib/GF256.h"
#include <random>
#include <ctime>

class SSS
{
private:
    int s, k, n;
    static std::mt19937 gen;
    GF256 * X;
    GF256 * S;
    GF256 * A;
    void restoreA();
public:
    SSS();
    SSS(int &s, int &k, int &n, uint8_t * X);
    void create(int &s, int &k, int &n, uint8_t * X);
    ~SSS();
    static uint8_t randbyte(uint8_t a=0, uint8_t b=255);
    uint8_t * share(uint8_t secret);
    uint8_t * secshare();
    static uint8_t restore(uint8_t * X, uint8_t * V, int n);
};


#endif //AESSECRETSHARING_SSS_H
