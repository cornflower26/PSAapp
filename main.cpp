#include <iostream>
//#include <core/lattice/lat-hal.h>
#include <pke/openfhe.h>


namespace lbcrypto {
    int main() {
        std::cout << "Hello, World!" << std::endl;
        //DCRTPoly a = DCRTPoly();

        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(5);
        parameters.SetScalingModSize(10);
        return 0;
    }
}
