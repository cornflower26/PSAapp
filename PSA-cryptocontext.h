//
// Created by Antonia Januszewicz on 3/27/24.
//

#ifndef OPENFHE_PSA_CRYPTOCONTEXT_H
#define OPENFHE_PSA_CRYPTOCONTEXT_H

#include "slaprns-scheme.h"

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
    long double epsilon = 2.0f;
    BasicInteger plainBits;
    unsigned int numUsers;
    unsigned int iters;
    long double scale = 0.5f;
    unsigned int maxCtexts = 20;
    unsigned int kPrime;
    unsigned int N;
    uint64_t ts = 0;

public:
    SLAPScheme aggregator;

    std::vector<DCRTPoly> privateKeys;
    DCRTPoly aggregationKey;
    DCRTPoly publicKey;

    std::vector<DCRTPoly> ciphertexts;
    std::vector<DCRTPoly> plaintexts;

    DiscreteLaplacianGenerator dl;

    PSACryptocontext(unsigned int t, unsigned int n,
                    unsigned int i, Scheme scheme1);

    void calculateParams();

    void genSlapScheme();

    void TestEncryption(const unsigned int iters, const bool do_noise, std::vector<double>& noise_times,
                    std::vector<double>& enc_times);

    void TestDecryption(const unsigned int iters, std::vector<double> & dec_times);

    void TestPolynomialEncryption(const bool do_noise, const unsigned int iters, std::vector<double>& noise_times,
                        std::vector<double>& enc_times);

    void TestPolynomialDecryption(const unsigned int iters, std::vector<double> & dec_times);


};

#endif  //OPENFHE_PSA_CRYPTOCONTEXT_H
