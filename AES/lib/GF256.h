#ifndef AES_GF256_H
#define AES_GF256_H

#include <cstdint>
#include <fstream>

// Поле Галуа 2^8 над многочленом x^8+x^4+x^3+x+1
class GF256
{
private:
    static const uint8_t dg[256];
    static const uint8_t lg[256];
    static const uint8_t Sbox[256];
    static const uint8_t InvSbox[256];
    uint8_t number = 0;
public:
    explicit GF256(uint8_t number=0);
    ~GF256();

    GF256& operator=(const int& other);
    GF256 operator+(const GF256& other) const;
    GF256 operator-(const GF256& other) const;
    GF256 operator*(const GF256& other) const;
    GF256 operator/(const GF256& other) const;
    GF256 pow(int degree);
    bool operator==(const GF256& other) const;
    bool operator!=(const GF256& other) const;
    GF256 operator~() const;
    explicit operator int() const;

    friend std::ostream& operator<<(std::ostream& out, const GF256& p);

    GF256 getSbox();
    GF256 getInvSbox();
    uint8_t getNumber();
};


#endif //AES_GF256_H
