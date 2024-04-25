//
// Created by Antonia Januszewicz on 3/27/24.
//

#ifndef OPENFHE_PSA_BASE_SCHEME_H
#define OPENFHE_PSA_BASE_SCHEME_H

#include "utils.cpp"
#include "PSA-constants.h"
#include "dgsampler.h"
#include <core/lattice/lat-hal.h>


using namespace lbcrypto;

class PSAScheme {
protected:
    Scheme scheme = NS;
    uint64_t ts = 0;
    double scale;
public:
    DCRTPoly ciphertextParams;
    DCRTPoly plaintextParams;
    DiscreteGaussianGeneratorImpl<DCRTPoly> * agg_dgg;
    DiscreteLaplacianGenerator dl;

    PSAScheme(){};

    void SecretKey(DCRTPoly& aggregationKey, std::vector<DCRTPoly>& privateKeys, int numUsers, bool dummy = false);

    DCRTPoly PublicKey(const uint64_t ts, bool dummy=false);

    virtual DCRTPoly Encrypt(const DCRTPoly plaintext, const DCRTPoly privateKey, const DCRTPoly publicKey,
                           const bool do_noise,
                           double & noise_time, double & enc_time) = 0;

     DCRTPoly NSEncrypt(const DCRTPoly plaintext, const DCRTPoly privateKey, const DCRTPoly publicKey) {return DCRTPoly();};
     DCRTPoly MSEncrypt(const DCRTPoly plaintext, const DCRTPoly privateKey, const DCRTPoly publicKey) {return DCRTPoly();};

    virtual DCRTPoly Decrypt(std::vector<DCRTPoly> ciphertexts, const DCRTPoly aggregationKey, const DCRTPoly publicKey,
                           double & dec_time, unsigned int num_additions=0) = 0;

    virtual DCRTPoly Decrypt(std::vector<DCRTPoly> ciphertexts, const DCRTPoly aggregationKey, const uint64_t ts,
                             double & dec_time, unsigned int num_additions=0) = 0;

    DCRTPoly NSDecrypt(const std::vector<DCRTPoly> ciphertexts,const DCRTPoly aggregationKey, const DCRTPoly publicKey,
                                unsigned int num_additions=0) {return DCRTPoly();};
    DCRTPoly MSDecrypt(const std::vector<DCRTPoly> ciphertexts,const DCRTPoly aggregationKey, const DCRTPoly publicKey,
                       unsigned int num_additions=0) {return DCRTPoly();};


    DCRTPoly PolynomialEncrypt(const DCRTPoly plaintext, const DCRTPoly privateKey, const DCRTPoly publicKey,
                                        bool do_noise, double & noise_time,
                                        double & enc_time, const uint64_t e){ return DCRTPoly();};

    std::vector<double> PolynomialDecrypt(std::vector<DCRTPoly> ciphertexts, const DCRTPoly aggregationKey, const DCRTPoly publicKey,
                                 double & dec_time, unsigned int num_additions=0){ return std::vector<double>();}

    std::vector<double> PolynomialDecrypt(std::vector<DCRTPoly> ciphertexts, const DCRTPoly aggregationKey, const uint64_t ts,
                                         double & dec_time, unsigned int num_additions=0){ return std::vector<double>();}

    virtual ~PSAScheme() {};
};

#endif  //OPENFHE_PSA_BASE_SCHEME_H
