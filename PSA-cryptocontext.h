//
// Created by Antonia Januszewicz on 3/27/24.
//

#ifndef OPENFHE_PSA_CRYPTOCONTEXT_H
#define OPENFHE_PSA_CRYPTOCONTEXT_H

#include "PSA-constants.h"
#include "slaprns-scheme.h"
#include <core/lattice/lat-hal.h>
#include <scheme/bfvrns/bfvrns-cryptoparameters.h>

using namespace lbcrypto;

//Lower than necessary - just in case
static const unsigned int PLAIN_MOD_SIZE_MAX = 50;
static const float SCALE_DEFAULT = 0.5f;

class PSACryptocontext {
private:
    Scheme scheme = NS;
    long double b = 0.0f;
    long double gamma = 0.0f;
    long double a = 0.0f;
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
    SLAPScheme aggregator;

    std::vector<DCRTPoly> privateKeys;
    DCRTPoly aggregationKey;
    DCRTPoly publicKey;

    std::vector<DCRTPoly> ciphertexts;
    std::vector<DCRTPoly> plaintexts;

    DiscreteLaplacianGenerator dl;

    PSACryptocontext(unsigned int t, unsigned int w, unsigned int n,
                    unsigned int i, Scheme scheme1);

    void calculateParams();

    void genSlapScheme();

    void TestEncryption(const bool do_noise, const unsigned int num_to_generate, std::vector<double>& noise_times,
                        std::vector<double>& enc_times);

    void TestDecryption();

    void TestPolynomialEncryption(const bool do_noise, const unsigned int num_to_generate, std::vector<double>& noise_times,
                        std::vector<double>& enc_times);

    void TestPolynomialDecryption();


};

#endif  //OPENFHE_PSA_CRYPTOCONTEXT_H
