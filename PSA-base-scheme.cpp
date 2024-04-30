//
// Created by Antonia Januszewicz on 3/30/24.
//

#include "PSA-base-scheme.h"

PSAScheme::PSAScheme(Scheme scheme, double scale) {
    this->scheme = scheme;
    this->scale = scale;
    ts = 0xDEADBEEF;
}

DCRTPoly PSAScheme::PublicKey(const uint64_t ts, bool dummy){
    DCRTPoly pk = ciphertextParams.CloneParametersOnly();
    //make a new noise vector and add it? direct access?
    //dl.refresh(ts);
    if(!dummy){
        pk.AddRandomNoise(pk.GetModulus());
    }
    else{
        pk.SetValuesToZero();
    }
    return pk;
}

void PSAScheme::SecretKey(DCRTPoly& aggregationKey, std::vector<DCRTPoly>& privateKeys, int num_users, bool dummy){
    aggregationKey.SetValuesToZero();
    privateKeys.clear();
    privateKeys.reserve(num_users);

    DCRTPoly result_template = aggregationKey.CloneParametersOnly();
    privateKeys.resize(num_users, result_template);
    for(unsigned int i = 0; i < num_users; i++){
#ifdef DEBUG
        assert(secret_keys[i].buffer() != NULL);
#endif
        if(!dummy){
            //privateKeys[i].error(this->dl);
            //dl.addRandomNoise(privateKeys[i],scale);
            privateKeys[i].AddRandomNoise(privateKeys[i].GetModulus());
        }
        else{
            privateKeys[i].SetValuesToZero();
        }

        aggregationKey -= privateKeys[i];
    }
    return;
}
