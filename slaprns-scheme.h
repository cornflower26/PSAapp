//
// Created by Antonia Januszewicz on 3/27/24.
//

#ifndef OPENFHE_SLAPRNS_H
#define OPENFHE_SLAPRNS_H

#include "PSA-base-scheme.h"
#include <core/lattice/lat-hal.h>
#include <scheme/bfvrns/bfvrns-cryptoparameters.h>
#include <scheme/ckksrns/cryptocontextparams-ckksrns.h>

using namespace lbcrypto;

class SLAPScheme : public PSAScheme {
private:
    CryptoParametersBFVRNS cryptoParams;
    CCParams<CryptoContextCKKSRNS> CKKSparameters;
    CryptoContext<DCRTPoly> CKKSContext;

public:
    std::vector<BigInteger> delta_mod_q;
    std::vector<BigInteger> t_mod_q;


    SLAPScheme(Scheme scheme, double scale);

    DCRTPoly Encrypt(const DCRTPoly plaintext, const DCRTPoly privateKey, const DCRTPoly publicKey,
                             const bool do_noise,
                             double & noise_time, double & enc_time) override;

    DCRTPoly NSEncrypt(const DCRTPoly plaintext, const DCRTPoly privateKey, const DCRTPoly publicKey);
    DCRTPoly MSEncrypt(const DCRTPoly plaintext, const DCRTPoly privateKey, const DCRTPoly publicKey);

    DCRTPoly Decrypt(std::vector<DCRTPoly> ciphertexts, const DCRTPoly aggregationKey, const uint64_t ts,
                             double & dec_time, unsigned int num_additions=0) override;

    DCRTPoly Decrypt(std::vector<DCRTPoly> ciphertexts, const DCRTPoly aggregationKey, const DCRTPoly publicKey,
                     double & dec_time, unsigned int num_additions=0) override;

    DCRTPoly NSDecrypt(const std::vector<DCRTPoly> ciphertexts,const DCRTPoly aggregationKey, const DCRTPoly publicKey,
                       unsigned int num_additions=0);
    DCRTPoly MSDecrypt(const std::vector<DCRTPoly> ciphertexts,const DCRTPoly aggregationKey, const DCRTPoly publicKey,
                       unsigned int num_additions=0);

    void SwitchBasis(DCRTPoly & ciphertext);

    DCRTPoly PolynomialEncrypt(const std::vector<double> plaintext, const DCRTPoly privateKey, const DCRTPoly publicKey,
                               bool do_noise, double & noise_time,
                               double & enc_time, const uint64_t e);

    std::vector<double> PolynomialDecrypt(std::vector<DCRTPoly> ciphertexts, const DCRTPoly aggregationKey, const DCRTPoly publicKey,
                                         double & dec_time, unsigned int num_additions=0);

    std::vector<double> PolynomialDecrypt(std::vector<DCRTPoly> ciphertexts, const DCRTPoly aggregationKey, const uint64_t ts,
                                         double & dec_time, unsigned int num_additions=0);


    ~SLAPScheme() {};

};



#endif  //OPENFHE_SLAPRNS_H
