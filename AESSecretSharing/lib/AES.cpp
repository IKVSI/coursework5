#include <cstring>
#include <iostream>
#include <sstream>
#include <iomanip>
#include "AES.h"

const GF256 AES::C[4][4] = {
        GF256(2), GF256(3), GF256(1), GF256(1),
        GF256(1), GF256(2), GF256(3), GF256(1),
        GF256(1), GF256(1), GF256(2), GF256(3),
        GF256(3), GF256(1), GF256(1), GF256(2)
};

const GF256 AES::InvC[4][4] = {
        GF256(14), GF256(11), GF256(13), GF256(9),
        GF256(9), GF256(14), GF256(11), GF256(13),
        GF256(13), GF256(9), GF256(14), GF256(11),
        GF256(11), GF256(13), GF256(9), GF256(14)
};

const GF256 AES::Rcon[16] = {
        GF256(1), GF256(2), GF256(4), GF256(8),
        GF256(16), GF256(32), GF256(64), GF256(128),
        GF256(27), GF256(54), GF256(108), GF256(216),
        GF256(171), GF256(77), GF256(154), GF256(47)
};

AES::AES(uint8_t *key)
{
    for(int i=0; i<32; ++i) this->key[i] = GF256(key[i]);
    this->KeyExpansion();
}

void AES::RotWord(GF256 *temp)
{
    GF256 a = temp[0];
    temp[0] = temp[1];
    temp[1] = temp[2];
    temp[2] = temp[3];
    temp[3] = a;
}

void AES::SubWord(GF256 *temp)
{
    for(int i=0; i<4; ++i) temp[i] = temp[i].getSbox();
}

void AES::KeyExpansion()
{
    int k = 0;
    for(int i=0; i<2; ++i)
    {
        for(int j=0; j<4; ++j)
        {
            for(int l=0; l<4; ++l)
            {
                this->w[i][l][j] = this->key[k];
                ++k;
            }
        }
    }
    GF256 temp[4] = {this->w[1][0][3], this->w[1][1][3], this->w[1][2][3], this->w[1][3][3]};
    for(int i=2; i<15; ++i)
    {
        if (i&1)
        {
            AES::SubWord(temp);
        }
        else
        {
            AES::RotWord(temp);
            AES::SubWord(temp);
            temp[0] = temp[0] + Rcon[i/2-1];
        }
        for(int j=0; j<4; ++j)
        {
            for(int k=0; k<4; ++k)
            {
                this->w[i][k][j] = this->w[i-2][k][j] + temp[k];
                temp[k] = this->w[i][k][j];
            }
        }
    }
}

void AES::SubBytes()
{
    for(int i=0; i<4; ++i)
    {
        for(int j=0; j<4; ++j)
        {
            this->state[i][j] = this->state[i][j].getSbox();
        }
    }
}

void AES::ShiftRows()
{
    GF256 temp[4];
    for(int i=1; i<4; ++i)
    {
        for(int j=0; j<4; ++j)
        {
            temp[j] = this->state[i][(j+i)%4];
        }
        for(int j=0; j<4; ++j)
        {
            this->state[i][j] = temp[j];
        }
    }
}

void AES::MixColumns()
{
    for(int i=0; i<4; ++i)
    {
        GF256 temp[4] = { GF256(0), GF256(0), GF256(0), GF256(0)};
        for(int j=0; j<4; ++j)
        {
            for(int k=0; k<4; ++k)
            {
                temp[j] = temp[j] + C[j][k] * this->state[k][i];
            }
        }
        for(int j=0; j<4; ++j)
        {
            this->state[j][i] = temp[j];
        }
    }
}

void AES::AddRoundKey(int round)
{
    for(int i=0; i<4; ++i)
    {
        for(int j=0; j<4; ++j)
        {
            this->state[i][j] = this->state[i][j] + w[round][i][j];
        }
    }
}

uint8_t *AES::encrypt(uint8_t * in)
{
    for(int i=0, k=0; i<4; ++i)
    {
        for(int j=0; j<4; ++j)
        {
            this->state[j][i] = GF256(in[k]);
            ++k;
        }
    }
    this->AddRoundKey(0);
    for(int i=1; i<14; ++i)
    {
        this->SubBytes();
        this->ShiftRows();
        this->MixColumns();
        this->AddRoundKey(i);
    }
    this->SubBytes();
    this->ShiftRows();
    this->AddRoundKey(14);
    uint8_t * out = new uint8_t[16];
    for(int i=0, k=0; i<4; ++i)
    {
        for(int j=0; j<4; ++j)
        {
            out[k] = this->state[j][i].getNumber();
            ++k;
        }
    }
    return out;
}

void AES::InvSubBytes()
{
    for(int i=0; i<4; ++i)
    {
        for(int j=0; j<4; ++j)
        {
            this->state[i][j] = this->state[i][j].getInvSbox();
        }
    }
}

void AES::InvShiftRows()
{
    GF256 temp[4];
    for(int i=1; i<4; ++i)
    {
        for(int j=0; j<4; ++j)
        {
            temp[j] = this->state[i][(((j-i)%4+4)%4)];
        }
        for(int j=0; j<4; ++j)
        {
            this->state[i][j] = temp[j];
        }
    }
}

void AES::InvMixColumns()
{
    for(int i=0; i<4; ++i)
    {
        GF256 temp[4] = { GF256(0), GF256(0), GF256(0), GF256(0)};
        for(int j=0; j<4; ++j)
        {
            for(int k=0; k<4; ++k)
            {
                temp[j] = temp[j] + InvC[j][k] * this->state[k][i];
            }
        }
        for(int j=0; j<4; ++j)
        {
            this->state[j][i] = temp[j];
        }
    }
}

uint8_t *AES::decrypt(uint8_t *out)
{
    for(int i=0, k=0; i<4; ++i)
    {
        for(int j=0; j<4; ++j)
        {
            this->state[j][i] = GF256(out[k]);
            ++k;
        }
    }
    this->AddRoundKey(14);
    for(int i=13; i>0; --i)
    {
        this->InvShiftRows();
        this->InvSubBytes();
        this->AddRoundKey(i);
        this->InvMixColumns();
    }
    this->InvShiftRows();
    this->InvSubBytes();
    this->AddRoundKey(0);
    uint8_t * in = new uint8_t[16];
    for(int i=0, k=0; i<4; ++i)
    {
        for(int j=0; j<4; ++j)
        {
            in[k] = this->state[j][i].getNumber();
            ++k;
        }
    }
    return in;
}

std::string AES::getKey()
{
    std::stringstream r;
    for(int i=0; i<4; ++i)
        for(int i=0; i<32; ++i)
        {
            r << std::setbase(16) << this->key[i] << ' ';
        }
    return r.str();
}

std::string AES::getState()
{
    std::stringstream r;
    for(int i=0; i<4; ++i)
    {
        for(int j=0; j<4; ++j)
        {
            r << std::setw(2) << std::setfill('0') << std::setbase(16) << this->state[i][j] << ' ';
        }
        r << '\n';
    }
    r << '\n';
    return r.str();
}

std::string AES::getW()
{
    std::stringstream r;
    for(int i=0; i<15; ++i)
    {
        r << "Round " <<i<<":\n";
        for(int j=0; j<4; ++j)
        {
            for(int k=0; k<4; ++k)
            {
                r << std::setw(2) << std::setfill('0') << std::setbase(16) << this->w[i][k][j];
            }
            r << '\n';
        }
    }
    return r.str();
}
