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
    gamma /= numUsers;


    //Directly from the paper
    if(b == 0.0f){
        static const unsigned int B_SCALE = 10;
        b = (long double) 1/gamma;
        b /= numUsers;
        long double tmp = log(1/delta);
        //b *= tmp;
        unsigned int b_int = B_SCALE*b;
        unsigned int tmp_int = B_SCALE*tmp;
        tmp_int *= b_int;
        b = ((long double)tmp_int)/(B_SCALE*B_SCALE);
    }

    a = 1/gamma;
    if (!isfinite(a)) throw std::invalid_argument("Infinite a");
    a *= log(1/delta);
    if (!isfinite(a)) throw std::invalid_argument("Infinite a");
    a *= log(2/b);
    if (!isfinite(a)) throw std::invalid_argument("Infinite a");
    a = sqrt(a);
    if (!isfinite(a)) throw std::invalid_argument("Infinite a");
    a *= (4*del_interval)/(long double)epsilon;
    if (!isfinite(a)) throw std::invalid_argument("Infinite a");
    return;
}

void PSACryptocontext::genSlapScheme() {

    auto q = aggregator.ciphertextParams.GetModulus();
    N = aggregator.ciphertextParams.GetNumOfElements();
            //ctext_parms->poly_mod_degree();

    unsigned int plain_mod_size = plainBits < PLAIN_MOD_SIZE_MAX ? plainBits : PLAIN_MOD_SIZE_MAX;
    unsigned int num_plain_moduli = plainBits / packingSize;
    if(!num_plain_moduli){
        num_plain_moduli += 1;
    }

    std::shared_ptr<ILDCRTParams<BigInteger>> parms = GenerateDCRTParams<BigInteger>(StdLatticeParm::FindRingDim(HEStd_ternary, HEStd_128_classic, static_cast<usint>(plainBits)),
            numTowers(plainBits),plainBits);
    aggregator.plaintextParams = DCRTPoly(parms,COEFFICIENT);

    BigInteger t = aggregator.plaintextParams.GetModulus();

    //I feel like this is wrong
    kPrime = aggregator.ciphertextParams.GetParams()->GetParams().size();
    //mod_count

    aggregator.delta_mod_q.reserve(kPrime);
    aggregator.t_mod_q.reserve(kPrime);


    BigInteger tmp;
    BigInteger delta = q/t;
    ///BigInteger tmp_mod;
    //Fill delta mod q for later scaling
    for(size_t i = 0; i < kPrime; i++){
        BigInteger qi = aggregator.ciphertextParams.GetElementAtIndex(i).GetModulus();
        BigInteger tmp_delta, tmp_t;
        //TODO fix - don't write directly to array
        //tmp_mod = qi.ConvertToLongDouble();
        tmp = delta % qi;
        tmp_delta = tmp;
        aggregator.delta_mod_q[i] = tmp_delta;
        tmp = t % qi;
        tmp_t = tmp;
        aggregator.t_mod_q[i] = tmp_t;
    }

}

PSACryptocontext::PSACryptocontext(unsigned int t, unsigned int w,
                                 unsigned int n, unsigned int i, Scheme scheme1) : aggregator(scheme, scale) {
    plainBits = t;
    packingSize = w;
    numUsers = n;
    iters = i;
    scheme = scheme1;


    NativeInteger NumUsers = NativeInteger(numUsers);
    unsigned int log_num_users = NumUsers.GetLengthForBase(2);
    //ceil of log or self make
    if(hammingWeight(numUsers) != 1){
        log_num_users++;
    }
    packingSize = packingSize + log_num_users;
    unsigned int log_q;
    if(scheme == NS){
        log_q = (plainBits+1) + log_num_users + LOG2_3;
    }
    else{
        log_q = 2*(plainBits+1) + log_num_users + LOG2_3;
    }

    std::shared_ptr<ILDCRTParams<BigInteger>> parms = GenerateDCRTParams<BigInteger>(StdLatticeParm::FindRingDim(HEStd_ternary, HEStd_128_classic, static_cast<usint>(ceil(log_q / log(2)))),
                                                                                     numTowers(log_q/plainBits),log_q/plainBits);
    aggregator.ciphertextParams = DCRTPoly(parms,COEFFICIENT);
    genSlapScheme();
    calculateParams();

    aggregator.Init();

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
        dl.addRandomNoise(input, scale, UNIFORM);
        //input.AddRandomNoise(input.GetModulus());
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
    std::vector<double> inputvec;
    //TODO Change
    inputvec.reserve(input.GetNumOfElements());

    //unsigned int users = aggregator.user_count();
    ciphertexts.reserve(numUsers);
    aggregator.SecretKey(aggregationKey, privateKeys, numUsers);
    //Polynomial result(params_pair.first);
    DCRTPoly result = aggregator.ciphertextParams.CloneParametersOnly();
    for(unsigned int i = 0; i < numUsers; i++){
        //First, get some random vector for user input
        dl.addRandomNoise(input, scale, UNIFORM);
        dl.addRandomNoise(inputvec, scale, UNIFORM);
        //Then, do the encryption
        double noise_time, enc_time;
        result = aggregator.PolynomialEncrypt(inputvec, privateKeys[i], publicKey,
                              do_noise,
                              noise_time, enc_time,1);
        if(i < num_to_generate){
            ciphertexts.push_back(result); //Hope this copies it
        }

        noise_times.push_back(noise_time);
        enc_times.push_back(enc_time);

        input.SetValuesToZero();
        inputvec.clear();
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