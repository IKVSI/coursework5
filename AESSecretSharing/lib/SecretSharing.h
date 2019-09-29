#ifndef AESSECRETSHARING_SECRETSHARING_H
#define AESSECRETSHARING_SECRETSHARING_H

#include "GF256.h"

class SecretSharing
{
private:
    GF256 secret;
public:
    SecretSharing();
    ~SecretSharing();
};


#endif //AESSECRETSHARING_SECRETSHARING_H
