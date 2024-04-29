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

static void ppow(DCRTPoly & rop, const  DCRTPoly& a, const uint64_t exp) {
    auto values = a.GetAllElements();
    BigVector ans(values.size(), 5);

    std::vector<int> mods;
    mods.reserve(a.GetParams()->GetParams().size());
    for (auto& p : a.GetParams()->GetParams())
        mods.emplace_back(p->GetModulus().ConvertToInt());

    for(size_t mod_idx = 0; mod_idx < mods.size(); mod_idx++) {
        uint64_t modulus = mods[mod_idx];
        auto temp = values[mod_idx].GetValues();
        for (size_t coeff_idx = 0; coeff_idx < temp.GetLength(); coeff_idx++) {
            uint128_t tmp = pow(temp[coeff_idx].ConvertToInt(), exp);
            //a.at(coeff_idx).ConvertToInt()
            tmp %= modulus;
            values[mod_idx].at(coeff_idx) = tmp;
        }
        rop.SetElementAtIndex(mod_idx, values[mod_idx]);

    }
}



static size_t choose_parameters(unsigned int required_q) {
    size_t n;
        //Ok
        if (required_q <= 27) {n = 1 << 10;}
            //This is the problematic one
        else if (required_q <= 54) {n = 1 << 11;}
            //Ok
        else if (required_q <= 109) {n = 1 << 12;}
            //Ok
        else if (required_q <= 218) { n = 1 << 13;}
            //Also problematic
        else if (required_q <= 438) { n = 1 << 14;}
            //Also problematic
        else if (required_q <= 881) { n = 1 << 15;}
        else {n = 0;}
        return n;
    }

#endif