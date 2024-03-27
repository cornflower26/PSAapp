//
// Created by Antonia Januszewicz on 3/27/24.
//

#ifndef OPENFHE_PSA_BASE_SCHEME_H
#define OPENFHE_PSA_BASE_SCHEME_H

#include "PSA-constants.h"
#include "lattice/lat-hal.h"
#include <OpenFHE>
#include <NTL/zz.h>



namespace lbcrypto {


class PSAScheme {
private:
    ILDCRTParams<NativeInteger> ciphertextParams;
    ILDCRTParams<NativeInteger> plaintextParams;

public:

    virtual void SecretKey(DCRTPoly& aggregationKey, std::vector<DCRTPoly>& privateKeys, bool dummy = false);

    virtual DCRTPoly PublicKey(const uint64_t ts, bool dummy=false);

    virtual DCRTPoly Encrypt(const DCRTPoly plaintext, const DCRTPoly privateKey,
                           bool do_noise,
                           double & noise_time, double & enc_time);

    virtual DCRTPoly NSEncrypt(const DCRTPoly plaintext, const DCRTPoly privateKey, const DCRTPoly publicKey);
    virtual DCRTPoly MSEncrypt(const DCRTPoly plaintext, const DCRTPoly privateKey, const DCRTPoly publicKey);

    virtual DCRTPoly Decrypt(std::vector<DCRTPoly> ciphertexts, const DCRTPoly aggregationKey, const DCRTPoly publicKey,
                           double & dec_time, unsigned int num_additions=0);

    virtual DCRTPoly Decrypt(std::vector<DCRTPoly> ciphertexts, const DCRTPoly aggregationKey, const uint64_t ts,
                             double & dec_time, unsigned int num_additions=0);

    DCRTPoly NSDecrypt(const std::vector<DCRTPoly> ciphertexts,const DCRTPoly aggregationKey, const DCRTPoly privateKey,
                                unsigned int num_additions=0);
    DCRTPoly MSDecrypt(const std::vector<DCRTPoly> ciphertexts,const DCRTPoly aggregationKey, const DCRTPoly privateKey,
                       unsigned int num_additions=0);


    DCRTPoly PolynomialEncrypt(const DCRTPoly plaintext, const DCRTPoly privateKey, const DCRTPoly publicKey,
                                        bool do_noise, double & noise_time,
                                        double & enc_time, const uint64_t e){ return DCRTPoly();};

    std::vector<float> PolynomialDecrypt(std::vector<DCRTPoly> ciphertexts, const DCRTPoly aggregationKey, const DCRTPoly publicKey,
                                 double & dec_time, unsigned int num_additions=0){ return std::vector<float>();}

    std::vector<float> PolynomialDecrypt(std::vector<DCRTPoly> ciphertexts, const DCRTPoly aggregationKey, const uint64_t ts,
                                         double & dec_time, unsigned int num_additions=0){ return std::vector<float>();}
};
}
#endif  //OPENFHE_PSA_BASE_SCHEME_H
