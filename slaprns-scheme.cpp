//
// Created by Antonia Januszewicz on 3/27/24.
//

#include "slaprns-scheme.h"

using namespace lbcrypto;

DCRTPoly SLAPScheme::Encrypt(const DCRTPoly plaintext, const DCRTPoly privateKey,
                 bool do_noise,
                 double & noise_time, double & enc_time){
    DCRTPoly noisy_input = plaintext;
    if(do_noise){
        noisy_input.add_dp_noise(this->dl, num, den);
    }
    else{
        noise_time = 0.0;
    }
    //Now get key and do encryption
    DCRTPoly pk = PublicKey(ts);
    DCRTPoly enc_result = (scheme==NS)? NSEncrypt(privateKey, noisy_input, pk) : MSEncrypt(privateKey, noisy_input, pk);
    return enc_result;
}

DCRTPoly SLAPScheme::NSEncrypt(const DCRTPoly plaintext, const DCRTPoly privateKey, const DCRTPoly publicKey){
    //Multiply secret and public keys
    DCRTPoly ret = privateKey*publicKey;
    //Get the error, and scale it by the plaintext modulus
    DCRTPoly e(this->ctext_parms);
    //TODO replace this - taken out for debugging
    e.error(this->dl);
    //e.zero();
    e *= t_mod_q; //Per-modulus scaling
    //Add in the error to make a RLWE term
    ret += e;
    //Raise x to base q
    DCRTPoly x_raised = ret.SwitchCRTBasis(something);
            //x.base_conv(ctext_parms, *t_to_q);
    //Now add the message
    ret += x_raised;
    return ret;
}

DCRTPoly SLAPScheme::MSEncrypt(const DCRTPoly plaintext, const DCRTPoly privateKey, const DCRTPoly publicKey){
    //Multiply secret and public keys
    DCRTPoly ret = privateKey*publicKey;
    //Get the error, and scale it by the plaintext modulus
    DCRTPoly e(this->ctext_parms);
    e.error(this->dl);
    //Add in the error to make a RLWE term
    ret += e;
    //Raise x to base q
    DCRTPoly x_raised = ret.SwitchCRTBasis(something);
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

DCRTPoly NSDecrypt(const std::vector<DCRTPoly> ciphertexts,const DCRTPoly aggregationKey, const DCRTPoly publicKey,
                   unsigned int num_additions=0){

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
    return ret.SwitchCRTBasis(something);
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
    return ret.SwitchCRTBasis(something);
}