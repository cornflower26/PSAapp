//
// Created by Antonia Januszewicz on 3/27/24.
//

#ifndef OPENFHE_PSA_CRYPTOCONTEXT_H
#define OPENFHE_PSA_CRYPTOCONTEXT_H

#include "PSA-constants.h"
#include "PSA-base-scheme.h"
#include <core/lattice/lat-hal.h>
#include <scheme/bfvrns/bfvrns-cryptoparameters.h>

using namespace lbcrypto;

class PSACryptoconext {
private:
    Scheme scheme = NS;
    long double b;
    long double gamma;
    long double a;
    long double delta = 0.1f;
    long double epsilon = 1.0f;
    BasicInteger plainBits;
    unsigned int packingSize;
    unsigned int numUsers;
    unsigned int iters;
    long double scale = 0.5f;
    unsigned int maxCtexts = 20;
    unsigned int kPrime;
    unsigned int N;

public:
    PSAScheme aggregator;

    std::vector<DCRTPoly> privateKeys;
    DCRTPoly aggregationKey;
    DCRTPoly publicKey;

    std::vector<DCRTPoly> ciphertexts;
    std::vector<DCRTPoly> plaintexts;

    PSACryptoconext(unsigned int t, unsigned int w, unsigned int n,
                    unsigned int i, unsigned int k, unsigned int N, Scheme scheme1);

    void calculateParams();

    void genSlapScheme();

    void TestEncryption(const bool do_noise, const unsigned int num_to_generate, std::vector<double>& noise_times,
                        std::vector<double>& enc_times);

    void TestPolynomialEncryption(const bool do_noise, const unsigned int num_to_generate, std::vector<double>& noise_times,
                        std::vector<double>& enc_times);


};

#endif  //OPENFHE_PSA_CRYPTOCONTEXT_H
