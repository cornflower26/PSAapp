#include <iostream>
//#include <core/lattice/lat-hal.h>
#include <pke/openfhe.h>



    int main() {
        std::cout << "Hello, World!" << std::endl;
        //DCRTPoly a = DCRTPoly();

        lbcrypto::CCParams<lbcrypto::CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(5);
        parameters.SetScalingModSize(10);
        return 0;
    }

