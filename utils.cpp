//
// Created by Antonia Januszewicz on 4/16/24.
//
#ifndef OPENFHE_UTILS_H
#define OPENFHE_UTILS_H

#include <encoding/plaintext.h>
using namespace lbcrypto;

// Function to calculate the Hamming weight
static unsigned int hammingWeight(unsigned int n) {
    unsigned int count = 0;
    while (n) {
        count += n & 1;
        n >>= 1;
    }
    return count;
}

static std::vector<double> Polynomial_to_double_encoding(const DCRTPoly & p){
    std::vector<double> ret;
    ret.resize(p.GetModulus().ConvertToInt());
    for(size_t i = 0; i < ret.size(); i++){
        ret[i] = p[i].ConvertToDouble();
    }
    return ret;
}

static DCRTPoly encoding_to_Polynomial(const Plaintext & vals, const DCRTPoly parms){
    DCRTPoly ret = parms.CloneParametersOnly();
    auto intermediate1 = vals->GetPackedValue();
    BigVector intermediate2(intermediate1.size(),parms.GetModulus());
    //Technically not the most efficient iteration order for cache coherency
    for(size_t i = 0; i < intermediate1.size(); i++){
        intermediate2 = (BigInteger(intermediate1[i]));
    }
    ret.SetValues(intermediate2, COEFFICIENT);
    return ret;
}
/**
void ppow(DCRTPoly & rop, const  DCRTPoly& a, const uint64_t exp) {

    size_t n = a.poly_mod_degree();
    for(size_t mod_idx = 0; mod_idx < ; mod_idx++) {
        uint64_t modulus = a.parms->moduli_data[mod_idx];
        for(size_t coeff_idx = 0; coeff_idx < n; coeff_idx++) {
            uint128_t tmp = pow(a.at(coeff_idx).ConvertToInt(),exp);
            tmp %= modulus;
            *rop_ptr = (uint64_t) tmp;
            a_ptr++;
            rop_ptr++;
        }
    }
}**/

#endif