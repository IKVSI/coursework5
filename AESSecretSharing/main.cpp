#include <iostream>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <ctime>
#include "lib/SSS.h"
#include "../AES/lib/AES.h"
#include <regex>
#define nS 32
#define BSIZE 134217728
/*
#define S 5
#define K 8
#define N 10
*/

clock_t TIME = 0;
clock_t REAL_TIME;
clock_t ALLTIME;

void startall()
{
	ALLTIME = std::clock();
}

void stopall()
{
	ALLTIME = std::clock() - ALLTIME;
}

void stop()
{
	TIME += std::clock() - REAL_TIME;
}
void start()
{
	REAL_TIME = std::clock();
}

void time(clock_t temp)
{
	clock_t h = temp / 3600000;
	temp %= 3600000;
	clock_t m = temp / 60000;
	temp %= 60000;
	clock_t s = temp / 1000;
	temp %= 1000;
	std::cout << "TIME: " << h << "h : " << m << "m : " << s << "s." << temp << '\n';
}

void help()
{
	std::cout << '\n';
    std::cout << "USE: AESSecretSharing.exe encrypt(e) [K] [S] [N] [key file] [input file]\n\n";
    std::cout << "USE: AESSecretSharing.exe decrypt(d) [K] [key file] [output file]\n\n";
    std::cout << "K           -   number of shares to restore information\n";
    std::cout << "S           -   number of AES encrypted shares\n";
    std::cout << "N           -   number of all shares\n";
    std::cout << "S >= 2 and N > K to avoid 1 fail; N < S + K because you must use 1 S-share; S < K => K >= 3 to share secret\n";
    std::cout << "key file    -   path to file; use first 32 byte of file for encryption key\n";
    std::cout << "input file  -   path to file for ecnrypt\n";
    std::cout << "output file -   path to files for decrypt\n";
    std::cout << "File encrypt in shares named:\n\t \"input file.enc\" - encrypted shares\n\t \"input file.shr\" - open shares\n";
    std::cout << "So if you want to restore file, you must have k-shares named filename(.enc/.shr).\n\n";
    std::cout << "USE: AESSecretSharing.exe help(h)\n\tShow help\n\n";
}

void error(int num)
{
    std::cout << "\n!!!Something goes wrong!!!\n";
	switch (num)
	{
	case 1:
		std::cout << "Wrong number of arguments!\n";
		break;
	case 2:
		std::cout << "Wrong mode!\n";
		break;
	case 3:
		std::cout << "Wrong constant!\n";
		break;
	case 4:
		std::cout << "Can't read 32 bytes from key file!\n";
		break;
	case 5:
		std::cout << "Can't find K files or .shr file\n";
		break;
	}
    help();
    exit(num);
}

uint8_t * createX(int &n)
{
    uint8_t temp[256] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
            0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
            0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
            0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
            0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
            0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
            0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
            0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
            0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
            0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
    };
    uint8_t * X = new uint8_t[n];
    for(int i=0; i<n; ++i)
    {
        uint8_t x = SSS::randbyte(1+i, 255);
        X[i] = temp[x];
        temp[x] = temp[1+i];
        temp[1+i] = X[i];
    }
    return X;
}

std::ofstream * createFiles(int &n, int &s, const char * filename)
{
    std::ofstream * fout = new std::ofstream[n];
    int i = 0;
    std::stringstream name;
    while(i < s)
    {
        name << filename << '.' << std::setbase(16) << std::setfill('0') << std::setw(2) << i << ".enc";
        fout[i].open(name.str(), std::fstream::binary);
        //std::cout<<name.str()<<'\n';
        name.str("");
        ++i;
    }
    while(i < n)
    {
        name << filename << '.' << std::setbase(16) << std::setfill('0') << std::setw(2) << i << ".shr";
        fout[i].open(name.str(), std::fstream::binary);
        //std::cout<<name.str()<<'\n';
        name.str("");
        ++i;
    }
    return fout;
}

void encrypt(int &k, int &s, int &n, uint8_t * key, const char * filename)
{
    // Создание X-ов
    uint8_t * X = createX(n);
    // Проверка файла секрета
    std::ifstream fin(filename, std::fstream::binary);
    uint8_t * bin = new uint8_t[BSIZE];
    fin.read((char *)bin, 1);
    if (fin.fail()) error(4);
    fin.clear();
    fin.seekg(0, std::ios::beg);
    // Создание файлов разделений
    std::ofstream * fout = createFiles(n, s, filename);
    uint8_t ** bout = new uint8_t * [n];
    for(int i=0; i<s; ++i) bout[i] = new uint8_t[nS];
    for(int i=s; i<n; ++i) bout[i] = new uint8_t[BSIZE];
	// Инициализация шифра
	AES cipher = AES(key);
	
    // Запись X значений файлов
    for(int i=0; i<n; ++i) fout[i].write((char*)&X[i], 1);
	start();
    // Создание шифрованных секретов
    SSS shares[nS];
    for(int i=0; i<nS; ++i) shares[i].create(s, k, n, X);
	stop();
    // Запись шифрованных секретов
    for(int i=0; i<nS; ++i)
    {
        uint8_t * temp = shares[i].secshare();
        for(int j=0; j<s; ++j)
        {
            bout[j][i] = temp[j];
        }
        delete [] temp;
    }
    for(int i=0; i<s; ++i)
    {
        for(int j=0; j<nS; j += 16)
        {
            uint8_t *temp = cipher.encrypt(&bout[i][j]);
            std::memcpy(&bout[i][j], temp, 16);
            delete [] temp;
        }
    }
	stop();
    for(int i=0; i<s; ++i) fout[i].write((char *) bout[i], nS);
    // Генерация остальных секретов
    int is = 0;
    int ns = n - s;
    while(!fin.eof())
    {
        fin.read((char *) bin, BSIZE);
        int length = fin.gcount();
		start();
        for(int i=0; i<length; ++i)
        {
            uint8_t * temp = shares[is].share(bin[i]);
            for(int j=0; j<ns; ++j)
            {
                bout[j+s][i] = temp[j];
            }
            delete [] temp;
            is = (is + 1) % nS;
        }
		stop();
        for(int i=ns; i<n; ++i)
        {
            fout[i].write((char *)bout[i], length);
        }
    }
	for (int i = 0; i < k; ++i) fout[i].flush();
	// Измерение времени
	time(TIME);
    // Освобождение памяти
    for(int i=0; i<n; ++i) delete [] bout[i];
    delete [] bout;
    delete [] bin;
    delete [] fout;
    delete [] X;
}

std::ifstream * findshares(int k, int &s,  const char * filename)
{
	std::filesystem::path abspath = std::filesystem::absolute(filename);
	std::string name = abspath.filename().string();
	std::vector<std::string> fsharesnames;
	const std::regex re(name+"\\.\\d+\\.(enc|shr)");
	for (auto i : std::filesystem::directory_iterator(abspath.parent_path()))
	{
		if (i.is_regular_file() && std::regex_search(i.path().string(), re))
		{
			fsharesnames.push_back(i.path().string());
		}
	}
	if ((fsharesnames.size() < k) || (fsharesnames[k].back() != 'r')) return nullptr;
	std::ifstream* fin = new std::ifstream[k];
	--k;
	fin[k].open(fsharesnames[k], std::fstream::binary);
	for (int i = 0; i < k; ++i)
	{
		if (fsharesnames[i].back() == 'c')
		{
			fin[i].open(fsharesnames[i], std::fstream::binary);
			++s;
		}
		else fin[i].open(fsharesnames[i], std::fstream::binary);
	}
	return fin;
}

void decrypt(int &k, uint8_t * key, const char * filename)
{
	// Собираем набор разделений
	int s = 0;
	std::ifstream * fin = findshares(k, s, filename);
	if (!fin) error(5);
	// Открываем файл для записи
	std::filesystem::path temp = std::filesystem::absolute(filename);
	temp.replace_filename("new_" + temp.filename().string());
	std::ofstream fout(temp, std::fstream::binary);
	// Создаём буфферы для файлов
	uint8_t** bin = new uint8_t * [k];
	for (int i = 0; i < s; ++i) bin[i] = new uint8_t[nS];
	for (int i = s; i < k; ++i) bin[i] = new uint8_t[BSIZE];
	uint8_t* bout = new uint8_t[BSIZE];
	// Инициализация шифра
	AES cipher = AES(key);
	// Читаем X-ы
	uint8_t* X = new uint8_t[k];
	for (int i = 0; i < k; ++i) fin[i].read((char *)&X[i], 1);
	//Расшифровываем S-разделения
	for (int i = 0; i < s; ++i)
	{
		fin[i].read((char*)bin[i], nS);
		start();
		for (int j = 0; j < nS; j += 16)
		{
			uint8_t* temp = cipher.decrypt(&bin[i][j]);
			std::memcpy(&bin[i][j], temp, 16);
			delete[] temp;
		}
		stop();
	}
	// Собираем секрет
	int is = 0;
	int length;
	do
	{
		length = -1;
		for (int i = s; i < k; ++i)
		{
			fin[i].read((char*)bin[i], BSIZE);
			if (length == -1) length = fin[i].gcount();
			else if (length != fin[i].gcount()) error(6);
		}
		start();
		for (int i = 0; i < length; ++i, is = (is + 1) % nS)
		{
			uint8_t * V = new uint8_t[k];
			for (int j = 0; j < s; ++j) V[j] = bin[j][is];
			for (int j = s; j < k; ++j) V[j] = bin[j][i];
			bout[i] = SSS::restore(X, V, k);
			delete[] V;
		}
		stop();
		fout.write((char*)bout, length);
	} while (length == BSIZE);
	fout.flush();
	// Измерение времени
	time(TIME);
	// Освобождение выделенной памяти
	delete[] bout;
	delete[] X;
	for (int i = 0; i < k; ++i) delete[] bin[i];
	delete[] bin;
	for (int i = 0; i < k; ++i) if(fin[i].is_open()) fin[i].close();
	delete [] fin;
}
/*
GF256 opr(GF256** T, int n)
{
	//std::cout << n << '\n';
	if (n == 2) return T[0][0] * T[1][1] + T[0][1] * T[1][0];
	GF256** rT = new GF256*[n-1];
	GF256 r = GF256(0);
	for (int i = 0; i < n - 1; ++i) rT[i] = new GF256[n - 1];
	for (int i = 0; i < n; ++i)
	{
		if (T[0][i].getNumber() == 0) continue;
		int a = 0;
		for (int j = 1; j < n; ++j)
		{
			int b = 0;
			for (int k = 0; k < n; ++k)
			{
				if (k == i) continue;
				rT[a][b] = T[j][k];
				++b;
			}
			++a;
		}
		r = r + opr(rT, n - 1)* T[0][i];
	}
	for (int i = 0; i < n - 1; ++i) delete[] rT[i];
	delete[] rT;
	return r;
}

void test()
{
	//GF256 x0 = GF256(0x42), x1 = GF256(0xb2), x2 = GF256(0x12), x3 = GF256(0x41);
	GF256 x0 = GF256(1), x1 = GF256(3), x2 = GF256(5), x3 = GF256(7);
	GF256 Va2 = GF256(0x9d), Va3 = GF256(0x33), Vb2 = GF256(0x6c), Vb3 = GF256(0xd3);
	GF256 **T = new GF256*[8];
	for (int i = 0; i < 8; ++i) T[i] = new GF256[8];
	T[0][0] = 1; T[0][1] = x0; T[0][2] = x0 * x0; T[0][3] = 1; T[0][4] = 0; T[0][5] = 0; T[0][6] = 0; T[0][7] = 0;
	T[1][0] = 1; T[1][1] = x1; T[1][2] = x1 * x1; T[1][3] = 0; T[1][4] = 0; T[1][5] = 0; T[1][6] = 0; T[1][7] = 1;
	T[2][0] = 1; T[2][1] = x2; T[2][2] = x2 * x2; T[2][3] = 0; T[2][4] = 0; T[2][5] = 0; T[2][6] = 0; T[2][7] = 0;
	T[3][0] = 1; T[3][1] = x3; T[3][2] = x3 * x3; T[3][3] = 0; T[3][4] = 0; T[3][5] = 0; T[3][6] = 0; T[3][7] = 0;
	T[4][0] = 0; T[4][1] = 0; T[4][2] = 0; T[4][3] = 1; T[4][4] = 1; T[4][5] = x0; T[4][6] = x0 * x0; T[4][7] = 0;
	T[5][0] = 0; T[5][1] = 0; T[5][2] = 0; T[5][3] = 0; T[5][4] = 1; T[5][5] = x1; T[5][6] = x1 * x1; T[5][7] = 1;
	T[6][0] = 0; T[6][1] = 0; T[6][2] = 0; T[6][3] = 0; T[6][4] = 1; T[6][5] = x2; T[6][6] = x2 * x2; T[6][7] = 0;
	T[7][0] = 0; T[7][1] = 0; T[7][2] = 0; T[7][3] = 0; T[7][4] = 1; T[7][5] = x3; T[7][6] = x3 * x3; T[7][7] = 0;
	GF256 V[8] = { GF256(0), GF256(0), Va2, Va3, GF256(0),GF256(0),Vb2,Vb3 };
	std::cout << '\t';
	for (int i = 0; i < 8; ++i) std::cout << i << '\t';
	std::cout << "|\tV\n";
	for (int i = 0; i < 8; ++i)
	{
		std::cout << i << ':' << '\t';
		for (int j = 0; j < 8; ++j)
		{
			std::cout << T[i][j] << '\t';
		}
		std::cout << '|' << '\t' << V[i] <<'\n';
	}
	GF256 k = opr(T, 8);
	std::string r = "";
	std::cout << '\n' << "OPR = "<<k << '\n';
	for (int i = 0; i < 8; ++i)
	{
		if (T[i][i].getNumber() == 0)
		{
			int j = i+1;
			for (; j < 8; ++j) if (T[j][j].getNumber()) break;
			if (j == 8) break;
			GF256 p = V[j];
			V[j] = V[i];
			V[i] = p;
			for (int k = i; k < 8; ++k)
			{
				p = T[j][k];
				T[j][k] = T[i][k];
				T[i][k] = p;
			}
		}
		GF256 temp = ~T[i][i];
		for (int j = i; j < 8; ++j) T[i][j] = T[i][j] * temp;
		V[i] = V[i] * temp;

		for (int j = 0; j < 8; ++j) if (j != i)
		{
			temp = T[j][i];
			for (int k = i; k < 8; ++k)
			{
				T[j][k] = T[j][k] + temp * T[i][k];
				V[j] = V[j] + temp * V[i];
			}
		}
	}
	std::cout << "\n\t";
	for (int i = 0; i < 8; ++i) std::cout << i << '\t';
	std::cout << "|\tV\n";
	for (int i = 0; i < 8; ++i)
	{
		std::cout << i << ':' << '\t';
		for (int j = 0; j < 8; ++j)
		{
			std::cout << T[i][j] << '\t';
		}
		std::cout << '|' << '\t' << V[i] << '\n';
	}
	for (int i = 0; i < 8; ++i) delete[] T[i];
	delete[] T;
}
*/
int main(int argc, char * argv[])
{
    uint8_t key[32];
    if (argc < 2) error(1);
    if (!(strcmp(argv[1], "h") && strcmp(argv[1], "help"))) help();
    else if (!(strcmp(argv[1], "e") && strcmp(argv[1], "encrypt")))
    {
        if (argc < 7) error(1);
        int k = atoi(argv[2]);
        int s = atoi(argv[3]);
        int n = atoi(argv[4]);
        if (s < 2) error(3);
        if (n <= k) error(3);
        if (n >= s+k) error(3);
        if (s >= k) error(3);
        std::ifstream keyin(argv[5], std::fstream::binary);
        keyin.read((char *) key, 32);
        if (keyin.fail())
        {
            error(4);
        }
		startall();
        encrypt(k, s, n, key, argv[6]);
		stopall();
		std::cout << "ALL";
		time(ALLTIME);
    }
    else if (!(strcmp(argv[1], "d") && strcmp(argv[1], "decrypt")))
    {
		if (argc < 5) error(1);
		int k = atoi(argv[2]);
		if (k < 3) error(3);
        std::ifstream keyin(argv[3], std::fstream::binary);
        keyin.read((char *) key, 32);
        if (keyin.fail())
        {
            error(4);
        }
		startall();
        decrypt(k, key, argv[4]);
		stopall();
		std::cout << "ALL";
		time(ALLTIME);
    }
    else error(2);
    return 0;
}