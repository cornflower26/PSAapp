//#include <iostream>
//#include <core/lattice/lat-hal.h>
//#include <pke/openfhe.h>

#include "PSA-cryptocontext.h"
#include "openfhe.h"



    int main() {
        std::cout << "Hello, World!" << std::endl;
        //DCRTPoly a = DCRTPoly();
        unsigned int plain_bits = 9;
        unsigned int packing_size = 1;
        unsigned int num_users = 1;
        unsigned int iters = 1;
        unsigned int k_prime = 1;
        unsigned int N = 1;

        unsigned int MAX_CTEXTS_DEFAULT = 20;

        //temp();

        PSACryptocontext p = PSACryptocontext(plain_bits, packing_size, num_users, iters, MS);
        std::vector<double> noise_times;
        std::vector<double> enc_times;

        p.TestEncryption(1, MAX_CTEXTS_DEFAULT, noise_times, enc_times);

        p.TestDecryption();

        PSACryptocontext pp = PSACryptocontext(plain_bits, packing_size, num_users, iters, MS);

        std::vector<double> poly_noise_times;
        std::vector<double> poly_enc_times;

        pp.TestPolynomialEncryption(1, MAX_CTEXTS_DEFAULT, poly_noise_times, poly_enc_times);


        pp.TestPolynomialDecryption();

        return 0;
    }

