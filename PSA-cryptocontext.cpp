//
// Created by Antonia Januszewicz on 4/1/24.
//
#include "PSA-cryptocontext.h"
#define LOG2_3 2

using namespace lbcrypto;

void PSACryptoconext::calculateParams() {
    unsigned int del_interval = packingSize ? packingSize : log2(plainBits);
    if(del_interval < (epsilon/3)){
        return;
    }
    if(epsilon <= 0){
        return;
    }
    if(delta <= 0 || delta >= 1){
        return;
    }

    scale = del_interval / epsilon;
    gamma = log(1/delta);
    gamma /= N;


    //Directly from the paper
    if(b == 0.0f){
        static const unsigned int B_SCALE = 10;
        b = (long double) 1/gamma;
        b /= N;
        long double tmp = log(1/delta);
        //b *= tmp;
        unsigned int b_int = B_SCALE*b;
        unsigned int tmp_int = B_SCALE*tmp;
        tmp_int *= b_int;
        b = ((long double)tmp_int)/(B_SCALE*B_SCALE);
    }

    a = 1/gamma;
    if (isfinite(a)) throw std::invalid_argument("Infinite a");
    a *= log(1/delta);
    if (isfinite(a)) throw std::invalid_argument("Infinite a");
    a *= log(2/b);
    if (isfinite(a)) throw std::invalid_argument("Infinite a");
    a = sqrt(a);
    if (isfinite(a)) throw std::invalid_argument("Infinite a");
    a *= (4*del_interval)/(long double)epsilon;
    if (isfinite(a)) throw std::invalid_argument("Infinite a");
    return;
}

PSACryptoconext::PSACryptoconext(unsigned int t, unsigned int w,
                                 unsigned int n, unsigned int i, unsigned int k,
                                 unsigned int N, Scheme scheme1){
    plainBits = t;
    packingSize = w;
    numUsers = n;
    iters = i;
    kPrime = k;
    scheme = scheme1;
    this->N = N;

    if (kPrime < 1){
        throw std::invalid_argument("Invalid Argument kPrime Value");
    }

    NativeInteger NumUsers = NativeInteger(numUsers);
    unsigned int log_num_users = NumUsers.GetLengthForBase(2);

    packingSize = packingSize + log_num_users;

    if(NTL::weight(numUsers) != 1){
        log_num_users++;
    }
    unsigned int log_q;
    if(scheme == NS){
        log_q = (plainBits+1) + log_num_users + LOG2_3;
    }
    else{
        log_q = 2*(plainBits+1) + log_num_users + LOG2_3;
    }

    calculateParams();
}