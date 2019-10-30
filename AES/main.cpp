#include <iostream>
#include <iomanip>
#include <bitset>
#include <cstring>
#include <ctime>
#include "lib/AES.h"


#define BSIZE 134217728

clock_t TIME;

void start()
{
	TIME = std::clock();
}

void time()
{
	clock_t temp = std::clock() - TIME;
	clock_t h = temp / 3600000;
	temp %= 3600000;
	clock_t m = temp / 60000;
	temp %= 60000;
	clock_t s = temp / 1000;
	temp %= 1000;
	std::cout << "TIME: " << h << "h : " << m << "m : " << s << "s." << temp << '\n';
}
/*
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
            /*  0*//* 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
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
*/

void help()
{
	std::cout << "USE: AES.exe [mode] [key file] [input file] [output file]\n\n";
	std::cout << "mode        -   e[encrypt], d[decrypt]\n";
	std::cout << "key file    -   path to file; use first 32 byte of file for encryption key\n";
	std::cout << "input file  -   path to file for read  encrypt/decrypt information\n";
	std::cout << "output file -   path to file for write decrypt/encrypt information\n";
}

void err(int e)
{
	std::cout << '\n';
    switch (e)
    {
        case 1:
            std::cout << "You must have 4 arguments!!!\n" << std::flush;
            break;
        case 2:
            std::cout << "Mode incorrect!!!\n" << std::flush;
            break;
        case 4:
            std::cout << "Input failed!!!\n" << std::flush;
            break;
        case 5:
            std::cout << "Output failed!!!\n" << std::flush;
            break;
        case 3:
            std::cout << "Key failed!!!\n" << std::flush;
            break;
    }
    help();
}


int encrypt(AES &cipher, std::istream &fin, std::ostream &fout)
{
    uint8_t buffer[BSIZE];
	// ����� �������
	start();
    while(!fin.eof())
    {
        fin.read((char *)buffer, BSIZE);
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
        fout.write((char *)buffer, length);
    }
	fout.flush();
	// ��������� �������
	time();
    return 0;
}

int decrypt(AES &cipher, std::istream &fin, std::ostream &fout)
{
    uint8_t buffer[BSIZE], save[16];
	// ����� �������
	start();
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
	fout.flush();
	// ��������� �������
	time();
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
    if (!(strcmp(argv[1], "encrypt") && strcmp(argv[1], "e"))) mode = true;
    else if (!(strcmp(argv[1], "decrypt") && strcmp(argv[1], "d"))) mode = false;
    else
    {
        err(2);
        return 2;
    }
    std::ifstream keyin(argv[2], std::fstream::binary);
    std::ifstream fin(argv[3], std::fstream::binary);
    std::ofstream fout(argv[4], std::fstream::binary);
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