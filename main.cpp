//#include <core/lattice/lat-hal.h>
//#include <pke/openfhe.h>
#include <iostream>
#include <getopt.h>
#include <execinfo.h>
#include <signal.h>
#include <unistd.h>
#include <math/dftransform.h>
#include "PSA-cryptocontext.h"

void handler(int sig) {
    void *array[10];
    size_t size;

    // get void*'s for all entries on the stack
    size = backtrace(array, 10);

    // print out all the frames to stderr
    fprintf(stderr, "Error: signal %d:\n", sig);
    backtrace_symbols_fd(array, size, STDERR_FILENO);
    exit(1);
}

void FHE_test(int num_users){
    std::cout << "Hello, FHE World! " << std::endl;
    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> keys;
    //Encode Data
    uint32_t scaleModSize = 50;
    uint32_t batchSize = 32;
    CCParams<CryptoContextCKKSRNS> parameters;

    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
    parameters.SetSecretKeyDist(secretKeyDist);

    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1 << 12);

    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(batchSize);

    std::vector<uint32_t> levelBudget = {4, 4};
    uint32_t levelsAvailableAfterBootstrap = 10;
    usint depth = levelsAvailableAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(levelBudget, secretKeyDist);
    parameters.SetMultiplicativeDepth(depth);

    cc = (GenCryptoContext(parameters));

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(lbcrypto::FHE);
    //std::cout << "CKKS scheme " << i << " is using ring dimension " << cc[i]->GetRingDimension() << std::endl;

    usint ringDim = cc->GetRingDimension();
    usint numSlots = ringDim / 2;
    cc->EvalBootstrapSetup(levelBudget);

    keys = (cc->KeyGen());
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalBootstrapKeyGen(keys.secretKey, numSlots);

    std::vector<Ciphertext<DCRTPoly>> encryptedData;
    for (int i =  0; i < num_users; i++){
        int in = i;
        if (i == 0) in = 1;

        std::vector<double> inputvec(16, 0);
        inputvec[0] = in;
        //std::cout << "Input: " << i << inputvec << std::endl;
        Ciphertext<DCRTPoly> element;
        Plaintext pt = cc->MakeCKKSPackedPlaintext(inputvec);
        auto add = cc->Encrypt(keys.publicKey, pt);
        encryptedData.push_back(add);
    }

    std::string result;
    double final = 0;
    std::vector<Ciphertext<DCRTPoly>> res;
    res.push_back(encryptedData[0]);

    for (int i = 1; i < num_users; i++) {
        //std::cout << "Computing multiplication " << i << " at depth " << encryptedData[i]->GetLevel() <<std::endl;
        if (depth - encryptedData[i]->GetLevel() < 1) cc->EvalBootstrap(encryptedData[i]);
        auto temp = cc->EvalMult(encryptedData[0],encryptedData[i]);
        res.push_back(temp);
    }
    std::vector<double> intermediate_values;
    for (int i = 1; i < num_users; i++) {
        Plaintext plain;
        cc->Decrypt(keys.secretKey, res[i], &plain);
        auto finvec = plain->GetCKKSPackedValue();
        //std::cout << "Full value " << finvec << std::endl;
        intermediate_values.push_back(finvec[0].real());
    }
    for (size_t i = 0; i < num_users; i++) final += intermediate_values[i];
    std::cout << "Final FHE value " << final << std::endl;
}

void PPSA_test(int num_users){
    std::cout << "Hello, PPSA World! " << std::endl;
    //DCRTPoly a = DCRTPoly();
    unsigned int plain_bits = 20; //log t
    unsigned int iters = 1; //i
    unsigned int k_prime = 1; //k
    Scheme scheme1 = NS;

    unsigned int N; //N

    if(!plain_bits){
        throw std::runtime_error("Must have nonempty plaintext space");
    }
    if(!num_users){
        throw std::runtime_error("Must have at least some users");
    }
    if(!iters){
        throw std::runtime_error("Must have at least some iterations");
    }

    unsigned int MAX_CTEXTS_DEFAULT = 20;
    MAX_CTEXTS_DEFAULT = N;
    MAX_CTEXTS_DEFAULT = k_prime;
    k_prime = MAX_CTEXTS_DEFAULT;

    //temp();

    //Code for testing SLAP, which isn't what this paper is about
    int prob_num_times = num_users/(512) +1;


    PSACryptocontext pp = PSACryptocontext(plain_bits, num_users, iters, scheme1);
    int num_times = num_users/(pp.aggregator.plaintextParams.GetRingDimension() / 2) +1;
    std::vector<double> poly_noise_times;
    std::vector<double> poly_enc_times;

    //pp.TestPolynomialEncryption(true, iters, poly_noise_times, poly_enc_times);
    // pp.TestPolynomialEncryption(1, MAX_CTEXTS_DEFAULT, poly_noise_times, poly_enc_times);

    pp.PolynomialEnvSetup(poly_noise_times, poly_enc_times);
    int q = 0;

    for (unsigned int i = 0; i < num_users; i++) {
        //for (unsigned int j = 0; j < num_times; j++) {
            int in = i;
            int exp = 0;
            if (i == 0) {
                in = 1;
                exp = 1;
            }

            std::vector<double> inputvec(pp.aggregator.plaintextParams.GetRingDimension() / 2, in);
            std::vector<double> expvec(pp.aggregator.plaintextParams.GetRingDimension() / 2, exp);

            //if (i/(pp.aggregator.plaintextParams.GetRingDimension() / 2) == j)
                expvec[i % (pp.aggregator.plaintextParams.GetRingDimension() / 2)] = 1;
            //else expvec[i] = 1;

            //std::cout << i << " input: " << inputvec << " exp: " << expvec << std::endl;

            pp.PolynomialEncryption(inputvec, expvec, i, poly_noise_times, poly_enc_times);
            q++;
        //}
    }


    //std::cout << "Prob time " << prob_num_times*num_users << " actual inputs " << q << std::endl;
    std::vector<double> decrypt_times;
    std::vector<double> agg_times;

    //std::cout << "MOST IMPORTANT NUMBER" << pp.aggregator.plaintextParams.GetRingDimension()/2 << std::endl;
    std::vector<double> constants(pp.aggregator.plaintextParams.GetRingDimension()/2,1);
    std::vector<double> outputvec = pp.PolynomialDecryption(constants, iters, decrypt_times);
    double final = 0;

    for (size_t i = 0; i < num_users; i++) final += outputvec[i];
    std::cout << "Final PPSA output: " << outputvec << std::endl;

}

int main(int argc, char ** argv) {
    signal(SIGSEGV, handler);

    unsigned int num_users = 115200; //n
    std::cout << "Num users " << num_users << std::endl;

    PPSA_test(num_users);
    //FHE_test(num_users);

    return 0;
}



