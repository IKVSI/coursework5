

#include "SSS.h"
#include <ctime>
#include <iostream>

std::mt19937 SSS::gen = std::mt19937(std::time(nullptr));


SSS::~SSS()
{
    delete [] this->S;
    delete [] this->X;
    delete [] this->A;
}

uint8_t SSS::randbyte(uint8_t a, uint8_t b)
{
    unsigned int temp = b+1-a;
    return SSS::gen()%temp+a;
}

SSS::SSS(int &s, int &k, int &n, uint8_t *X)
{
    this->create(s, k, n, X);
}

uint8_t *SSS::share(uint8_t secret)
{
    this->A[0] = secret;
    int ks = this->k - this->s, ns =this->n - this->s;
    for(int i=1; i<ks; ++i) this->A[i] = SSS::randbyte(1,255);
    this->restoreA();
    GF256 * V = new GF256[ns];
    for(int i=0; i<ns; ++i)
    {
        V[i] = 0;
        GF256 x(1), Xi = this->X[i+this->s];
        for(int j=0; j<this->k; ++j)
        {
            V[i] = V[i] + x*this->A[j];
            x = x * Xi;
        }
    }
    uint8_t * rV = new uint8_t[ns];
    for(int i=0; i<ns; ++i) rV[i] = V[i].getNumber();
    //for(int i=0; i<n; ++i) std::cout<<"V"<<i<<" = "<<V[i]<<'\n';
    delete [] V;
    return rV;
}

uint8_t SSS::restore(uint8_t *x, uint8_t *v, int k)
{
    GF256 * X = new GF256[k];
    GF256 * V = new GF256[k];
    for(int i=0; i<k; ++i)
    {
        X[i] = x[i];
        V[i] = v[i];
    }
    GF256 A(0);
    for(int i=0; i<k; ++i)
    {
        GF256 temp(1);
        for(int j=0; j<k; ++j)
        {
            if (j == i) continue;
            temp = temp * X[j]/(X[j]+X[i]);
        }
        A = A+temp*V[i];
    }
    delete [] X;
    delete [] V;
    return A.getNumber();
}

void SSS::restoreA()
{
    GF256 * S = new GF256[s];
    int na = this->k - this->s;
    //for(int a=0; a<this->s;++a) std::cout<<"X"<<a<<" = "<<this->X[a]<<' '; std::cout<<'\n';
    for(int i=0; i<this->s; ++i)
    {
        GF256 temp(0), x(1);
        for(int j=0;j<na;++j)
        {
            temp = temp + this->A[j] * x;
            x = x * this->X[i];
        }
        S[i] = (this->S[i] + temp) / x;
    }
    for(int i=0; i<this->s; ++i)
    {
        GF256 A(0);
        for(int j=i; j<this->s;++j)
        {
            GF256 temp(1);
            for(int k=i; k<this->s; ++k)
            {
                if ( j == k ) continue;
                temp = temp * this->X[k]/(this->X[k]+this->X[j]);
            }
            A = A + temp*S[j];
        }
        this->A[na+i] = A;
        for(int j=0; j<this->s; ++j)
        {
            S[j] = (S[j]+A)/this->X[j];
        }
    }
    delete [] S;
}

SSS::SSS()
{

}

uint8_t * SSS::secshare()
{
    uint8_t * S = new uint8_t[this->s];
    for(int i=0; i<this->s; ++i) S[i] = this->S[i].getNumber();
    return S;
}

void SSS::create(int &s, int &k, int &n, uint8_t *X)
{
    this->s = s;
    this->k = k;
    this->n = n;
    this->X = new GF256[n];
    for(int i=0; i<n; ++i)  this->X[i] = X[i];
    this->S = new GF256[s];
    for(int i=0; i<s; ++i)
    {
        this->S[i] = SSS::randbyte();
    }
    this->A = new GF256[k];
}

