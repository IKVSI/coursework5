#include <iostream>
#include <iomanip>
#include <bitset>
#include <cstring>
#include "lib/AES.h"

#define BSIZE 32

void test()
{
    uint8_t key[32];
    for(uint8_t i=0; i<32; ++i)
    {
        key[i] = i;
        std::cout<<std::setbase(16)<<std::setw(2)<<std::setfill('0')<<int(key[i]);
    }
    std::cout<<'\n';
    AES cipher = AES(key);
    uint8_t text[16] = {
            //      0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
            /*  0*/ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    uint8_t *encrypttext, *decrypttext;
    for(uint8_t i=0; i<16; ++i)
    {
        std::cout<<std::setbase(16)<<std::setw(2)<<std::setfill('0')<<int(text[i]);
    }
    std::cout<<'\n';
    encrypttext = cipher.encrypt(text);
    for(uint8_t i=0; i<16; ++i)
    {
        std::cout<<std::setbase(16)<<std::setw(2)<<std::setfill('0')<<int(encrypttext[i]);
    }
    std::cout<<'\n';
    decrypttext = cipher.decrypt(encrypttext);
    for(uint8_t i=0; i<16; ++i)
    {
        std::cout<<std::setbase(16)<<std::setw(2)<<std::setfill('0')<<int(decrypttext[i]);
    }
    std::cout<<'\n';
    delete [] encrypttext;
    delete [] decrypttext;
}

void help()
{
    std::cout << std::flush;
    std::cout << "USE: AES.exe [key file] [input file] [output file] [mode]\n\n";
    std::cout << "key file    -   path to file; use first 32 byte of file for encryption key\n";
    std::cout << "input file  -   path to file for read  encrypt/decrypt information\n";
    std::cout << "output file -   path to file for write decrypt/encrypt information\n";
    std::cout << "mode        -   e[encrypt], d[decrypt]\n";
}

void err(int e)
{
    switch (e)
    {
        case 1:
            std::cerr << "You must have 4 arguments!!!\n" << std::flush;
            break;
        case 2:
            std::cerr << "Mode incorrect!!!\n" << std::flush;
            break;
        case 4:
            std::cerr << "Input failed!!!\n" << std::flush;
            break;
        case 5:
            std::cerr << "Output failed!!!\n" << std::flush;
            break;
        case 3:
            std::cerr << "Key failed!!!\n" << std::flush;
            break;
    }
    help();
}

void timeit(const char * mess, clock_t &start, clock_t &temp)
{
    clock_t t = clock();
    std::cout<<mess<<(t - start)<<" TIME:"<<(t-temp)<<'\n';
    temp = t;
}

int encrypt(AES &cipher, std::istream &fin, std::ostream &fout)
{
    uint8_t buffer[BSIZE];
    //clock_t start = clock(), temp=start;
    while(!fin.eof())
    {
        fin.read((char *)buffer, BSIZE);
        //timeit("READ   : ", start, temp);
        int length = fin.gcount();
        if (length < BSIZE)
        {
            int temp = 16-length%16;
            for(int i=0; i<temp; ++i, ++length) buffer[length] = temp;
        }
        for(int i=0; i<length;i+=16)
        {
            uint8_t * out = cipher.encrypt(&buffer[i]);
            std::copy(&out[0], &out[16], &buffer[i]);
            delete [] out;
        }
        //timeit("ENCRYPT: ", start, temp);
        fout.write((char *)buffer, length);
        fout.flush();
        //timeit("WRITE  : ", start, temp);
    }
    return 0;
}

int decrypt(AES &cipher, std::istream &fin, std::ostream &fout)
{
    uint8_t buffer[BSIZE], save[16];
    bool fl = false;
    while(!fin.eof())
    {
        fin.read((char *)buffer, BSIZE);
        int length = fin.gcount();
        if (fl && length) fout.write((char *)save, 16);
        for(int i=0; i<length;i+=16)
        {
            uint8_t * out = cipher.decrypt(&buffer[i]);
            std::copy(&out[0], &out[16], &buffer[i]);
            delete [] out;
        }
        if (length < BSIZE) length -= buffer[length-1];
        else
        {
            length -= 16;
            std::copy(&buffer[length], &buffer[BSIZE], save);
            if (fl) fl = false;
        }
        fout.write((char *) buffer, length);
        if (fl) continue;
        fl = true;
    }
    return 0;
}

int main(int argc, char * argv[])
{
    for(int i=1; i<argc; ++i)
    {
        if (!(strcmp(argv[i], "-h") && strcmp(argv[i], "--help") && strcmp(argv[i], "/?") && strcmp(argv[i], "?")))
        {
            help();
            return 0;
        }
    }
    if ((argc > 5) || (argc < 5))
    {
        err(1);
        return 1;
    }

    bool mode;
    if (!(strcmp(argv[4], "encrypt") && strcmp(argv[4], "e"))) mode = true;
    else if (!(strcmp(argv[4], "decrypt") && strcmp(argv[4], "d"))) mode = false;
    else
    {
        err(2);
        return 2;
    }
    std::ifstream keyin(argv[1], std::fstream::binary);
    std::ifstream fin(argv[2], std::fstream::binary);
    std::ofstream fout(argv[3], std::fstream::binary);
    uint8_t key[32];
    keyin.read((char *) key, 32);
    if (keyin.fail())
    {
        err(3);
        return 3;
    }
    AES cipher = AES(key);
    if (mode) encrypt(cipher, fin, fout);
    else decrypt(cipher, fin, fout);
    return 0;
}