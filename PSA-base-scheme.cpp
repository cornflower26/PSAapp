//
// Created by Antonia Januszewicz on 3/30/24.
//

#include "PSA-base-scheme.h"

PSAScheme::PSAScheme(Scheme scheme, double scale) {
    this->scheme = scheme;
    this->scale = scale;
}

void PSAScheme::PublicKey(DCRTPoly& pk, const uint64_t ts, bool dummy){
    pk = ciphertextParams.CloneParametersOnly();
    pk.SetValuesToZero();
    //make a new noise vector and add it? direct access?
    //dl.refresh(ts);
    //DCRTPoly jk = DCRTPoly(ciphertextParams.GetParams(),EVALUATION,true);
    if(!dummy){
        dl.addRandomNoise(pk,pk.GetModulus().ConvertToInt(),UNIFORM);
        //dl.uniform(jk);
    }
    else{
        pk.SetValuesToZero();
    }
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
            //privateKeys[i].AddRandomNoise(privateKeys[i].GetModulus());
            //privateKeys[i] = DCRTPoly(aggregationKey.GetParams());
            dl.addRandomNoise(privateKeys[i],3,UNIFORM);
            //dl.uniform(privateKeys[i]);
        }
        else{
            privateKeys[i].SetValuesToZero();
        }

        aggregationKey -= privateKeys[i];
    }
    return;
}
