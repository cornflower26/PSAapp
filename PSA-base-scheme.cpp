//
// Created by Antonia Januszewicz on 3/30/24.
//

#include "PSA-base-scheme.h"

DCRTPoly PSAScheme::PublicKey(const uint64_t ts, bool dummy){
    DCRTPoly pk(this->ctext_parms);
    dl.refresh(ts);
    if(!dummy){
        pk.uniform(dl);
    }
    else{
        pk.SetValuesToZero();
    }
    return pk;
}

void PSAScheme::SecretKey(DCRTPoly& aggregationKey, std::vector<DCRTPoly>& privateKeys, bool dummy){
    aggregationKey.SetValuesToZero();
    privateKeys.clear();
    privateKeys.reserve(num_users);

    DCRTPoly result_template(aggregationKey.parameters());
    privateKeys.resize(num_users, result_template);
    for(unsigned int i = 0; i < num_users; i++){
#ifdef DEBUG
        assert(secret_keys[i].buffer() != NULL);
#endif
        if(!dummy){
            privateKeys[i].error(this->dl);
        }
        else{
            privateKeys[i].SetValuesToZero();
        }

        aggregationKey -= privateKeys[i];
    }
    return;
}
