//
// Created by Antonia Januszewicz on 3/27/24.
//

#include <openfhe.h>
#include "slaprns-scheme.h"

using namespace lbcrypto;

SLAPScheme::SLAPScheme() : PSAScheme() {
    // Sample Program: Step 1 - Set CryptoContext


    CKKSparameters.SetMultiplicativeDepth(1);
    CKKSparameters.SetScalingModSize(scale);
    CKKSparameters.SetBatchSize(8);

    CKKSContext = GenCryptoContext(CKKSparameters);
}

void SLAPScheme::SwitchBasis(DCRTPoly & ciphertext) {

    DCRTPoly retValue = ciphertext.CloneEmpty();

    // converts to coefficient representation before rounding
    ciphertext.SetFormat(Format::COEFFICIENT);
        // Performs the scaling by t/Q followed by rounding; the result is in the
        // CRT basis P
        ciphertext =
                ciphertext.ScaleAndRound(cryptoParams.GetParamsRl(), cryptoParams.GettRSHatInvModsDivsModr(),
                                        cryptoParams.GettRSHatInvModsDivsFrac(), cryptoParams.GetModrBarrettMu());

        // Converts from the CRT basis P to Q
        ciphertext = ciphertext.SwitchCRTBasis(cryptoParams.GetElementParams(), cryptoParams.GetRlHatInvModr(),
                                             cryptoParams.GetRlHatInvModrPrecon(), cryptoParams.GetRlHatModq(),
                                             cryptoParams.GetalphaRlModq(), cryptoParams.GetModqBarrettMu(),
                                             cryptoParams.GetrInv());


    //retValue.SetElements(std::move(ciphertexts));

}

DCRTPoly SLAPScheme::Encrypt(const DCRTPoly plaintext, const DCRTPoly privateKey, const DCRTPoly publicKey,
        const bool do_noise,
        double & noise_time, double & enc_time){
    DCRTPoly noisy_input = plaintext;
    if(do_noise){
        //noisy_input.add_dp_noise(this->dl, num, den);
        dl.addRandomNoise(noisy_input,scale);
    }
    else{
        noise_time = 0.0;
    }
    //Now get key and do encryption
    DCRTPoly enc_result = (scheme==NS)? NSEncrypt(privateKey, noisy_input, publicKey) :
            MSEncrypt(privateKey, noisy_input, publicKey);
    return enc_result;
}

DCRTPoly SLAPScheme::NSEncrypt(const DCRTPoly plaintext, const DCRTPoly privateKey, const DCRTPoly publicKey){
    //Multiply secret and public keys
    DCRTPoly ret = privateKey*publicKey;
    //Get the error, and scale it by the plaintext modulus
    DCRTPoly e = ciphertextParams.CloneParametersOnly();
    //TODO replace this - taken out for debugging
    //e.error(this->dl);
    dl.addRandomNoise(e,scale);
    //e.zero();
    e *= t_mod_q; //Per-modulus scaling
    //Add in the error to make a RLWE term
    ret += e;
    //Raise x to base q
    DCRTPoly x_raised = ret.Clone();
    SwitchBasis(x_raised);
            //x.base_conv(ctext_parms, *t_to_q);
    //Now add the message
    ret += x_raised;
    return ret;
}

DCRTPoly SLAPScheme::MSEncrypt(const DCRTPoly plaintext, const DCRTPoly privateKey, const DCRTPoly publicKey){
    //Multiply secret and public keys
    DCRTPoly ret = privateKey*publicKey;
    //Get the error, and scale it by the plaintext modulus
    DCRTPoly e = ciphertextParams.CloneParametersOnly();
    //e.error(this->dl);
    dl.addRandomNoise(e,scale);
    //Add in the error to make a RLWE term
    ret += e;
    //Raise x to base q
    DCRTPoly x_raised = ret.Clone();
    SwitchBasis(x_raised);
    //DCRTPoly x_raised = ret.SwitchCRTBasis(something);
            //x.base_conv(ctext_parms, *t_to_q);
    //Scale x by delta
    x_raised *= delta_mod_q;
    //Now add the message
    ret += x_raised;
    return ret;
}

DCRTPoly SLAPScheme::Decrypt(std::vector<DCRTPoly> ciphertexts, const DCRTPoly aggregationKey, const uint64_t ts,
                 double & dec_time, unsigned int num_additions){
    DCRTPoly publicKey = PublicKey(ts);
    DCRTPoly ret = (scheme == NS) ?
            NSDecrypt(ciphertexts, aggregationKey, publicKey, num_additions) : MSDecrypt(ciphertexts, aggregationKey, publicKey, num_additions);
    return ret;
}

DCRTPoly SLAPScheme::Decrypt(std::vector<DCRTPoly> ciphertexts, const DCRTPoly aggregationKey, const DCRTPoly publicKey,
                 double & dec_time, unsigned int num_additions){
    DCRTPoly ret = (scheme == NS) ?
                   NSDecrypt(ciphertexts, aggregationKey, publicKey, num_additions) : MSDecrypt(ciphertexts, aggregationKey, publicKey, num_additions);
    return ret;
}

DCRTPoly SLAPScheme::NSDecrypt(const std::vector<DCRTPoly> ciphertexts,const DCRTPoly aggregationKey, const DCRTPoly publicKey,
                   unsigned int num_additions){

    DCRTPoly ret = aggregationKey*publicKey;
    if(!num_additions){
        num_additions = ciphertexts.size();
    }
    size_t num_ctexts = ciphertexts.size();
    size_t idx = 0;
    for(unsigned int i = 0; i < num_additions; i++,idx++){
        if(idx == num_ctexts){
            idx = 0;
        }
        ret += ciphertexts[idx];
    }
    //return ret.base_conv(plain_parms, *q_to_t);
    SwitchBasis(ret);
    return ret;
}

DCRTPoly SLAPScheme::MSDecrypt(const std::vector<DCRTPoly> ciphertexts,const DCRTPoly aggregationKey, const DCRTPoly publicKey,
                   unsigned int num_additions){
    DCRTPoly ret = aggregationKey*publicKey;
    //Add all the ciphertexts (mod q)
    if(!num_additions){
        num_additions = ciphertexts.size();
    }
    size_t num_ctexts = ciphertexts.size();
    size_t idx = 0;
    for(unsigned int i = 0; i < num_additions; i++,idx++){
        if(idx == num_ctexts){
            idx = 0;
        }
        ret += ciphertexts[idx];
    }
    //Now scale and reduce
    //return ret.scale_down(plain_parms, *q_to_t);
    SwitchBasis(ret);

    return ret;
}

DCRTPoly SLAPScheme::PolynomialEncrypt(const DCRTPoly plaintext, const DCRTPoly privateKey, const DCRTPoly publicKey,
                           bool do_noise, double & noise_time,
                           double & enc_time, const uint64_t e){

    //First, add differentially private noise to x
    //No easy way around copying x while keeping input clean
    DCRTPoly noisy_input = plaintext;
    if(do_noise){
        //noisy_input.ppow(noisy_input,noisy_input,e);
        //noisy_input.add_dpg_noise(this->dl, num, den);
        dl.addRandomNoise(noisy_input,scale);
    }
    else{
        noise_time = 0.0;
    }
    //Now get key and do encryption
    //Now get key and do encryption
#if CHRONO_TIME
    start = high_resolution_clock::now();
#endif
    auto float_result =  Polynomial_to_double_encoding(noisy_input);
    for (int i = 0; i < float_result.size(); i++){
        float_result.at(i) = log(float_result.at(i));
    }
    Plaintext ckks_result = CKKSContext->MakeCKKSPackedPlaintext(float_result);
    ckks_result->Encode();
    DCRTPoly poly_result = encoding_to_Polynomial(ckks_result,plaintext);

    DCRTPoly enc_result = (scheme==NS)? NSEncrypt(privateKey, noisy_input, publicKey) :
                          MSEncrypt(privateKey, noisy_input, publicKey);
    return enc_result;

};

std::vector<double> SLAPScheme::PolynomialDecrypt(std::vector<DCRTPoly> ciphertexts, const DCRTPoly aggregationKey, const DCRTPoly publicKey,
                                     double & dec_time, unsigned int num_additions){

    DCRTPoly ret = (scheme == NS) ?
                   NSDecrypt(ciphertexts, aggregationKey, publicKey, num_additions) : MSDecrypt(ciphertexts, aggregationKey, publicKey, num_additions);
    std::vector<double> int_result = Polynomial_to_double_encoding(ret);
    std::vector<std::complex<double>> cvec( int_result.size() );
    std::transform( int_result.begin(), int_result.end(), int_result.begin(), cvec.begin(), []( double da, double db ) {
        return std::complex<double>( da, db );});
    CKKSPackedEncoding float_result = CKKSPackedEncoding(cvec,0);
    float_result.Decode();
    auto intermediate1 = float_result.GetRealPackedValue();


    for (int i = 0; i < intermediate1.size(); i++){
        intermediate1.at(i) = exp(intermediate1.at(i));
    }

    return intermediate1;

}

std::vector<double> SLAPScheme::PolynomialDecrypt(std::vector<DCRTPoly> ciphertexts, const DCRTPoly aggregationKey, const uint64_t ts,
                                     double & dec_time, unsigned int num_additions){
    //high_resolution_clock::time_point start, end;
    //start = high_resolution_clock::now();
    DCRTPoly pk = PublicKey(ts);
    //end = high_resolution_clock::now();
    //double tmp = duration_cast<chrono::nanoseconds>(end-start).count();
    std::vector<double> ret = PolynomialDecrypt(ciphertexts, aggregationKey, pk, dec_time, num_additions);
    //dec_time += tmp; //Assume public key can be precomputed - TODO actually make this a compiletime or runtime choice
    return ret;

}
