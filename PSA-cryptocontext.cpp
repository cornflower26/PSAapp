//
// Created by Antonia Januszewicz on 4/1/24.
//
#include "PSA-cryptocontext.h"
#include <openfhe.h>
#include <core/lattice/lat-hal.h>
#include "utils/parmfactory.h"
#define LOG2_3 2

using namespace lbcrypto;

void PSACryptocontext::calculateParams() {
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

void PSACryptocontext::genSlapScheme() {

}

PSACryptocontext::PSACryptocontext(unsigned int t, unsigned int w,
                                 unsigned int n, unsigned int i, unsigned int k,
                                 unsigned int N, Scheme scheme1) : aggregator(scheme, scale) {
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
    //ceil of log or self make
    if(hammingWeight(numUsers) != 1){
        log_num_users++;
    }
    unsigned int log_q;
    if(scheme == NS){
        log_q = (plainBits+1) + log_num_users + LOG2_3;
    }
    else{
        log_q = 2*(plainBits+1) + log_num_users + LOG2_3;
    }

    //usint m = choose_parameters(log_q) << 1;
    std::shared_ptr<ILDCRTParams<BigInteger>> parms = GenerateDCRTParams<BigInteger>(StdLatticeParm::FindRingDim(HEStd_ternary, HEStd_128_classic, static_cast<usint>(ceil(log_q / log(2)))),1,log_q/plainBits);
    aggregator.ciphertextParams = DCRTPoly(parms,COEFFICIENT);

    static const float SCALE_DEFAULT = 0.5f;
    calculateParams();
}

void PSACryptocontext::TestEncryption(const bool do_noise, const unsigned int num_to_generate, std::vector<double>& noise_times,
                    std::vector<double>& enc_times){
    ciphertexts.clear();
    noise_times.clear();
    enc_times.clear();
    //auto params_pair = aggregator.parms_ptrs();
    DCRTPoly input = aggregator.plaintextParams.CloneParametersOnly();

    ciphertexts.reserve(numUsers);
    aggregator.SecretKey(aggregationKey, privateKeys, numUsers);
    DCRTPoly result = aggregator.ciphertextParams.CloneParametersOnly();
    for(unsigned int i = 0; i < numUsers; i++){
        //First, get some random vector for user input
        input.AddRandomNoise(input.GetModulus());
        //Then, do the encryption
        double noise_time, enc_time;
        result = aggregator.Encrypt(input, privateKeys[i], publicKey,
                         do_noise,
                         noise_time, enc_time);
        if(i < num_to_generate){
            //WARNING: don't push_back a temporary Polynomial. Just don't.
            ciphertexts.push_back(result); //Hope this copies it
        }

        noise_times.push_back(noise_time);
        enc_times.push_back(enc_time);
    }

}

void PSACryptocontext::TestPolynomialEncryption(const bool do_noise, const unsigned int num_to_generate, std::vector<double>& noise_times,
                              std::vector<double>& enc_times){
    ciphertexts.clear();
    noise_times.clear();
    enc_times.clear();
    //auto params_pair = agg.parms_ptrs();
    //DCRTPoly input(params_pair.first);
    DCRTPoly input = aggregator.plaintextParams.CloneParametersOnly();
    //unsigned int users = aggregator.user_count();

    ciphertexts.reserve(numUsers);
    aggregator.SecretKey(aggregationKey, privateKeys, numUsers);
    //Polynomial result(params_pair.first);
    DCRTPoly result = aggregator.ciphertextParams.CloneParametersOnly();
    for(unsigned int i = 0; i < numUsers; i++){
        //First, get some random vector for user input
        input.AddRandomNoise(input.GetModulus());
        //Then, do the encryption
        double noise_time, enc_time;
        result = aggregator.PolynomialEncrypt(input, privateKeys[i], publicKey,
                              do_noise,
                              noise_time, enc_time,1);
        if(i < num_to_generate){
            ciphertexts.push_back(result); //Hope this copies it
        }

        noise_times.push_back(noise_time);
        enc_times.push_back(enc_time);
        input.SetValuesToZero();
    }

}

void PSACryptocontext::TestDecryption(){
    DCRTPoly res = aggregator.ciphertextParams.CloneParametersOnly();
    std::vector<double> dec_times;
    for(unsigned int i = 0; i < iters; i++){
        double dec_time;
        res = aggregator.Decrypt(ciphertexts, aggregationKey, aggregator.ts, dec_time, numUsers);
        dec_times.push_back(dec_time);
    }
}

void PSACryptocontext::TestPolynomialDecryption(){
    std::vector<double> res;
    std::vector<double> mult_res;
    std::vector<double> dec_times;
    for(unsigned int i = 0; i < iters; i++){
        double dec_time;
        res = aggregator.PolynomialDecrypt(ciphertexts, aggregationKey, aggregator.ts, dec_time, numUsers);
        if (i == 0) for (int j = 0; j < mult_res.size(); j++) mult_res.at(j) *= res.at(j);
        else mult_res = res;
        //os << res << '\n';
        dec_times.push_back(dec_time);
    }
}