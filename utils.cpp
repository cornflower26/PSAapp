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
    ret.SetValues(intermediate2, EVALUATION);
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

    static size_t numTowers(unsigned int pbits){
    if (pbits < 64){
        return 1;
    }
    else if (pbits < 128){
        return 2;
    }
    else if (pbits < 192){
        return 3;
    }
    else if (pbits < 256){
        return 4;
    }
    else {
        return 0;
    }
}

template <typename P>
inline static void encodeVec(P& poly, const PlaintextModulus& mod, int64_t lb, int64_t ub,
                             const std::vector<int64_t>& value, SCHEME schemeID) {
    if (ub > INT32_MAX || lb < INT32_MIN)
        OPENFHE_THROW(config_error, "Cannot encode a coefficient larger than 32 bits");

    poly.SetValuesToZero();
    for (size_t i = 0; i < value.size() && i < poly.GetLength(); i++) {
        if (value[i] <= lb || value[i] > ub)
            OPENFHE_THROW(config_error, "Cannot encode integer " + std::to_string(value[i]) + " at position " +
                                        std::to_string(i) + " because it is out of range of plaintext modulus " +
                                        std::to_string(mod));

        typename P::Integer entry{value[i]};

        if (value[i] < 0) {
            if (schemeID == SCHEME::BFVRNS_SCHEME) {
                // TODO: Investigate why this doesn't work with q instead of t.
                uint64_t adjustedVal{mod - static_cast<uint64_t>(llabs(value[i]))};
                entry = typename P::Integer(adjustedVal);
            }
            else {
                // It is more efficient to encode negative numbers using the ciphertext
                // modulus no noise growth occurs
                entry = poly.GetModulus() - typename P::Integer(static_cast<uint64_t>(llabs(value[i])));
            }
        }
        poly[i] = entry;
    }
}

#endif