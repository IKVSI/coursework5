#include <iostream>
#include "lib/SSS.h"
#include "../AES/lib/GF256.h"
int main()
{
    uint8_t X[10];
    for(int i=0; i<10; ++i) X[i] = SSS::randbyte(1,255);
    //SSS scheme(2, 3, 4, X);
    SSS scheme(5, 8, 10, X);
    uint8_t * shares;
    shares = scheme.share('S');
    std::cout<<"secret = "<<SSS::restore(X, shares, 8)<<'\n';

    delete [] shares;
    return 0;
}