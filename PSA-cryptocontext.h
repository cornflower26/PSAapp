//
// Created by Antonia Januszewicz on 3/27/24.
//

#ifndef OPENFHE_PSA_CRYPTOCONTEXT_H
#define OPENFHE_PSA_CRYPTOCONTEXT_H

#include "PSA-constants.h"
#include "PSA-base-scheme.h"

namespace lbcrypto {

class PSACryptoconext {
private:
    Scheme scheme1 = NS;
    long double b;
    long double gamma;
    long double a;
    long double delta;
    long double epsilon;
    unsigned int plainBits;
    unsigned int packingSize;
    unsigned int numUsers;
    unsigned int iters;
    long double scale;
    unsigned int maxCtexts;
    unsigned int kPrime;

public:
    PSAScheme aggregator;

    std::vector<DCRTPoly> privateKeys;
    DCRTPoly aggregationKey;
    DCRTPoly publicKey;

    std::vector<DCRTPoly> ciphertexts;
    std::vector<DCRTPoly> plaintexts;

    void TestEncryption(const bool do_noise, const unsigned int num_to_generate, std::vector<double>& noise_times,
                        std::vector<double>& enc_times);

    void TestPolynomialEncryption(const bool do_noise, const unsigned int num_to_generate, std::vector<double>& noise_times,
                        std::vector<double>& enc_times);


};

#endif  //OPENFHE_PSA_CRYPTOCONTEXT_H
}