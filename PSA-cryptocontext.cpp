//
// Created by Antonia Januszewicz on 4/1/24.
//
#include "PSA-cryptocontext.h"
#define LOG2_3 2

using namespace lbcrypto;

void PSACryptocontext::calculateParams() {
    unsigned int del_interval = log2(plainBits);
    //unsigned int del_interval = packingSize ? packingSize : log2(plainBits);
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
    if (!std::isfinite(a)) throw std::invalid_argument("Infinite a");
    a *= log(1/delta);
    if (!std::isfinite(a)) throw std::invalid_argument("Infinite a");
    a *= log(2/b);
    if (!std::isfinite(a)) throw std::invalid_argument("Infinite a");
    a = sqrt(a);
    if (!std::isfinite(a)) throw std::invalid_argument("Infinite a");
    a *= (4*del_interval)/(long double)epsilon;
    if (!std::isfinite(a)) throw std::invalid_argument("Infinite a");

    aggregator.scale = scale;
    std::cout << "SCALE: " << aggregator.scale << std::endl;
    return;
}

void PSACryptocontext::genSlapScheme() {

    auto q = aggregator.ciphertextParams.GetModulus();
    N = aggregator.ciphertextParams.GetCyclotomicOrder();
            //ctext_parms->poly_mod_degree();

    unsigned int plain_mod_size = plainBits < PLAIN_MOD_SIZE_MAX ? plainBits : PLAIN_MOD_SIZE_MAX;
    //unsigned int num_plain_moduli = plainBits / packingSize;
    //if(!num_plain_moduli){
    //    num_plain_moduli += 1;
    //}

    std::cout << "Plain bits is " << plainBits << std::endl;
    std::cout << "Plain_mod_size is " << plain_mod_size << std::endl;
   // std::cout << "Num_plain_moduli is " << num_plain_moduli << std::endl;
    std::cout << "N is " << N << std::endl;
    std::shared_ptr<ILDCRTParams<BigInteger>> parms = GenerateDCRTParams<BigInteger>(N,
                numTowers(plain_mod_size),plain_mod_size);
    aggregator.plaintextParams = DCRTPoly(parms,EVALUATION);
    aggregator.plaintextParams.SetValuesToZero();
    //std::cout << "Plaintext, M: " << aggregator.ciphertextParams.GetCyclotomicOrder();
    //std::cout << ", Num of towers: " << num_plain_moduli;
    //std::cout << ", Log_t: " << plainBits << std::endl;

    BigInteger t = aggregator.plaintextParams.GetModulus();

    //I feel like this is wrong
    kPrime = aggregator.ciphertextParams.GetParams()->GetParams().size();
    //mod_count

    aggregator.delta_mod_q.resize(kPrime);
    aggregator.t_mod_q.resize(kPrime);


    //BigInteger tmp;
    BigInteger delta = q;
    delta %= t;
    ///BigInteger tmp_mod;
    //Fill delta mod q for later scaling
    for(size_t i = 0; i < kPrime; i++){
        BigInteger qi = aggregator.ciphertextParams.GetElementAtIndex(i).GetModulus();

        /**
        BigInteger tmp_delta, tmp_t;
        TODO fix - don't write directly to array
        tmp_mod = qi.ConvertToLongDouble();
        tmp = delta % qi;
        tmp_delta = tmp;
        aggregator.delta_mod_q[i] = tmp_delta;
        tmp = t % qi;
        tmp_t = tmp;
        aggregator.t_mod_q[i] = tmp_t;
         **/
        aggregator.delta_mod_q.at(i) = delta;
        aggregator.delta_mod_q.at(i) %= qi;
        aggregator.t_mod_q.at(i) = t;
        aggregator.t_mod_q.at(i) %= qi;
    }

}

PSACryptocontext::PSACryptocontext(unsigned int t,
                                 unsigned int n, unsigned int i, Scheme scheme1) : aggregator(scheme1, scale) {
    plainBits = t;
    //packingSize = w;
    numUsers = n;
    iters = i;
    scheme = scheme1;
    ts = 0xDEADBEEF;


    NativeInteger NumUsers = NativeInteger(numUsers);
    unsigned int log_num_users = NumUsers.GetLengthForBase(2);

    //ceil of log or self make
    if(hammingWeight(numUsers) != 1){
        log_num_users++;
    }
    //packingSize = packingSize + log_num_users;
    unsigned int log_q;
    if(scheme == NS){
        log_q = (plainBits+1) + log_num_users + LOG2_3;
    }
    else{
        log_q = 2*(plainBits+1) + log_num_users + LOG2_3;
    }

    std::shared_ptr<ILDCRTParams<BigInteger>> parms = GenerateDCRTParams<BigInteger>(choose_parameters(log_q),
                                                                                     numTowers(log_q),log_q);
    aggregator.ciphertextParams = DCRTPoly(parms,EVALUATION);
    aggregator.ciphertextParams.SetValuesToZero();

    //std::cout << "Ciphertext, M: " << choose_parameters(log_q);
    //std::cout << ", Num of towers: " << numTowers(log_q);
    //std::cout << ", Log_q: " << log_q << std::endl;
    genSlapScheme();
    calculateParams();

    aggregator.Init();

}

void PSACryptocontext::TestEncryption(const unsigned int iters, const bool do_noise, std::vector<double>& noise_times,
                    std::vector<double>& enc_times){
    ciphertexts.clear();
    noise_times.clear();
    enc_times.clear();
    //auto params_pair = aggregator.parms_ptrs();
    DCRTPoly input = aggregator.plaintextParams.CloneParametersOnly();
    input.SetValuesToZero();
    aggregationKey = aggregator.ciphertextParams.CloneParametersOnly();
    aggregationKey.SetValuesToZero();
    aggregator.PublicKey(publicKey, ts);

    //ciphertexts.reserve(numUsers);
    aggregator.SecretKey(aggregationKey, privateKeys, numUsers);
    DCRTPoly result = aggregator.ciphertextParams.CloneParametersOnly();
    result.SetValuesToZero();
    for(unsigned int i = 0; i < numUsers; i++){
        //First, get some random vector for user input
        dl.addRandomNoise(input, scale, UNIFORM);
        std::cout << "Input for aggregation " << input << std::endl;
        //input.AddRandomNoise(input.GetModulus());
        //Then, do the encryption
        double noise_time, enc_time;
        plaintexts.push_back(input);
        result = aggregator.Encrypt(input, privateKeys[i], publicKey,
                         do_noise,
                         noise_time, enc_time);
        std::cout << "Ciphertext for aggregation " << result << std::endl;
        ciphertexts.push_back(result);
        noise_times.push_back(noise_time);
        enc_times.push_back(enc_time);
        input.SetValuesToZero();
    }

}

void PSACryptocontext::TestPolynomialEncryption(const bool do_noise, const unsigned int iters, std::vector<double>& noise_times,
                              std::vector<double>& enc_times){
    //ciphertexts.clear();
    //plaintexts.clear();
    noise_times.clear();
    enc_times.clear();
    aggregationKey = aggregator.ciphertextParams.CloneParametersOnly();
    aggregationKey.SetValuesToZero();
    aggregator.PublicKey(publicKey, ts);
    std::vector<double> inputvec(aggregator.plaintextParams.GetRingDimension()/2,20000);
    //std::vector<double> inputvec = dl.GenerateIntVector(aggregator.plaintextParams.GetRingDimension()/2, 1, GAUSS);
    noise_times.reserve(iters);
    enc_times.reserve(iters);
    //TODO Change

    //unsigned int users = aggregator.user_count();
    //ciphertexts.reserve(numUsers);
    aggregator.SecretKey(aggregationKey, privateKeys, numUsers);
    if(privateKeys.empty()){
        throw std::logic_error("Must have at least one private key! (Probably at least 2...)");
    }
    //Polynomial result(params_pair.first);
    DCRTPoly result = aggregator.ciphertextParams.CloneParametersOnly();
    result.SetValuesToZero();
    //std::cout << "Scale is " << scale << std::endl;
    for(unsigned int i = 0; i < numUsers; i++){
        //First, get some random vector for user input
        //dl.addRandomNoise(inputvec, scale, UNIFORM);
        //Then, do the encryption
        double noise_time, enc_time;
        std::cout << inputvec << std::endl;
        result = aggregator.PolynomialEncrypt(inputvec, privateKeys.at(i % privateKeys.size()), publicKey,
                              do_noise,
                              noise_time, enc_time, 1);
        if(i < numUsers){
            ciphertexts.push_back(result); //Hope this copies it
            std::cout << result << std::endl;
        }
        noise_times.push_back(noise_time);
        enc_times.push_back(enc_time);
        //std::fill_n(inputvec.begin(), inputvec.size(), 1);
    }
    return;
}

void PSACryptocontext::TestDecryption(const unsigned int iters, std::vector<double> & dec_times){
    DCRTPoly res = aggregator.ciphertextParams.CloneParametersOnly();
    res.SetValuesToZero();
    for(unsigned int i = 0; i < iters; i++){
        double dec_time;
        res = aggregator.Decrypt(ciphertexts, aggregationKey, publicKey, dec_time, numUsers);
        dec_times.push_back(dec_time);
        std::cout << "Result of Aggregation: " << res << std::endl;
    }
}

//NB this is only testing one vector's decryption.

void PSACryptocontext::TestPolynomialDecryption(const unsigned int iters, std::vector<double> & dec_times){
    dec_times.clear();
    dec_times.reserve(iters);

    //Get some random inputs and keys
    //TODO check the scale argument to addRandomNoise
    //DCRTPoly reserve = aggregator.ciphertextParams.CloneParametersOnly();
    //reserve.SetValuesToZero();
    //this->ciphertexts = std::vector<DCRTPoly>(numUsers,reserve);

//    for(DCRTPoly & poly : this->ciphertexts){
//        dl.addRandomNoise(poly, this->scale, UNIFORM);
//    }
//    this->aggregationKey = aggregator.ciphertextParams.CloneParametersOnly();
//    aggregationKey.SetValuesToZero();
//    dl.addRandomNoise(aggregationKey, this->scale, UNIFORM);

    std::vector<double> result;

    for(unsigned int i = 0; i < iters; i++){
        double dec_time;
        double agg_time;
        auto begin = std::chrono::steady_clock::now();
        result = aggregator.PolynomialDecrypt(ciphertexts, aggregationKey, publicKey, dec_time, numUsers);
        auto end = std::chrono::steady_clock::now();
        std::cout << "Decryption result for PPSA " << result << std::endl;
        //No clue what this was supposed to do.
        /*
        if (i == 0){
            for (int j = 0; j < mult_res.size(); j++){
                mult_res.at(j) *= res.at(j);
            } 
        } 
        else {mult_res = res;}
        */
        //os << res << '\n';
        dec_times.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin).count());

    }
    return;
}