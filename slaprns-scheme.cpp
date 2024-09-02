//
// Created by Antonia Januszewicz on 3/27/24.
//

#include <chrono>

#include <omp.h>

#include "slaprns-scheme.h"
#include <math/dftransform.h>
#include <omp.h>

using namespace lbcrypto;
using namespace std::chrono;

using time_typ = std::chrono::nanoseconds;

SLAPScheme::SLAPScheme(Scheme scheme, double scale) : PSAScheme(scheme, scale) {
}

void SLAPScheme::Init(){
    // Sample Program: Step 1 - Set CryptoContext
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(plaintextParams.GetModulus().ConvertToInt());
    //536903681
    //std::cout << plaintextParams.GetModulus().ConvertToLongDouble() << std::endl;
    parameters.SetMultiplicativeDepth(1);
    parameters.SetMaxRelinSkDeg(2);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    // enable features that you wish to use
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);
    cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(cryptoContext->GetCryptoParameters());
    //auto crypto = cryptoContext->GetCryptoParameters();
    //auto crypto = cryptoContext->GetCryptoParameters();
    //auto cryptop = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(crypto);
    //auto cryptoParam = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(cryptoContext->GetCryptoParameters());
    //std::dynamic_pointer_cast<CryptoParametersBFVRNS>
    //int a = crypto->GetDigitSize();
    //int b = cryptop->GetDigitSize();
    //std::cout << a << b << std::endl;
    //cryptoParams = cryptoParam;



    CKKSparameters.SetMultiplicativeDepth(1);
    CKKSparameters.SetScalingModSize(25);
    //plaintextParams.GetModulus().GetLengthForBase(2)
    CKKSparameters.SetBatchSize(plaintextParams.GetRingDimension()/2);


    CKKSContext = GenCryptoContext(CKKSparameters);
}

std::vector<DoubleNativeInt> SLAPScheme::ComputeShit(DCRTPoly & plaintext){
    std::vector<DoubleNativeInt> m_modqBarrettMu;
    const BigInteger BarrettBase128Bit("340282366920938463463374607431768211456");  // 2^128
    const BigInteger TwoPower64("18446744073709551616");                            // 2^64
    m_modqBarrettMu.resize(plaintext.GetNumOfElements());
    for (uint32_t i = 0; i < plaintext.GetNumOfElements(); i++) {
        BigInteger mu = BarrettBase128Bit / BigInteger(plaintext.GetParams()->GetParams()[i]->GetModulus());
        uint64_t val[2];
        val[0] = (mu % TwoPower64).ConvertToInt();
        val[1] = mu.RShift(64).ConvertToInt();
        memcpy(&m_modqBarrettMu[i], val, sizeof(DoubleNativeInt));
    }
    return m_modqBarrettMu;
}

void SLAPScheme::ScaleDown(DCRTPoly & ciphertext, DCRTPoly & plaintext){
    //const auto t = plaintext.GetWorkingModulus();
    cryptoParams->SetPlaintextModulus(ciphertext.GetModulus().ConvertToInt());
    if(plaintext.GetNumOfElements() <= 0){
        throw std::logic_error("Not enough elements to get a meaningful index");
    }
    size_t index = plaintext.GetNumOfElements()-1;
    //size_t index = plaintext.GetNumOfElements()-1;
    //ciphertext.ModReduce(t, cryptoParams->GettModqPrecon(), cryptoParams->GetNegtInvModq(index),
    //            cryptoParams->GetNegtInvModqPrecon(index), cryptoParams->GetqlInvModq(index),
    //            cryptoParams->GetqlInvModqPrecon(index));
#ifdef _OPENMP
    omp_set_nested(false);
#endif
    ciphertext.ScaleAndRound(plaintext.GetParams(), cryptoParams->GettRSHatInvModsDivsModr(),
                                    cryptoParams->GettRSHatInvModsDivsFrac(), ComputeShit(plaintext));

    //ciphertext = ScaleAndRound(ciphertext, plaintext.GetParams(), cryptoParams->GettRSHatInvModsDivsModr(),
    //                           cryptoParams->GettRSHatInvModsDivsFrac(), ComputeShit(plaintext));
#ifdef _OPENMP
    omp_set_nested(true);
#endif

}

void SLAPScheme::SwitchBasis(DCRTPoly & ciphertext, DCRTPoly & plaintext) {
    //cryptoParams->SetElementParams(ciphertextParams.GetParams());
    //const auto cryptoParams   = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(ciphertext.GetCryptoParameters());
    //DCRTPoly retValue = ciphertext.CloneEmpty();
    //cryptoParams->SetPlaintextModulus(ciphertext.GetModulus().ConvertToLongDouble());

    // converts to coefficient representation before rounding
   // ciphertext.SetFormat(Format::COEFFICIENT);
        // Performs the scaling by t/Q followed by rounding; the result is in the
        // CRT basis P
        //ciphertext =
        //        ciphertext.ScaleAndRound(cryptoParams->GetParamsRl(), cryptoParams->GettRSHatInvModsDivsModr(),
        //                                cryptoParams->GettRSHatInvModsDivsFrac(), cryptoParams->GetModrBarrettMu());

        // Converts from the CRT basis P to Q
        //std::cout << ciphertext.GetModulus().ConvertToLongDouble() << " is the ciphertext modulus" << std::endl;
        //std::cout << plaintext.GetModulus().ConvertToLongDouble() << " is the plaintext modulus" << std::endl;
        cryptoParams->SetPlaintextModulus(plaintext.GetModulus().ConvertToInt());
        if(plaintext.GetNumOfElements() <= 0){
            throw std::logic_error("Not enough elements to get a meaningful index");
        }
        size_t index = plaintext.GetNumOfElements()-1;
#ifdef _OPENMP
        omp_set_nested(false);
#endif
        ciphertext =
                //SwitchCRTBasis1(plaintext.GetParams(), cryptoParams->GetRlHatInvModr(index),
                //                 cryptoParams->GetRlHatInvModrPrecon(index), cryptoParams->GetRlHatModq(index),
                //                 cryptoParams->GetalphaRlModq(index), cryptoParams->GetModqBarrettMu(),
                //                 cryptoParams->GetrInv(),ciphertext);

                ciphertext.SwitchCRTBasis(plaintext.GetParams(), cryptoParams->GetRlHatInvModr(index),
                                             cryptoParams->GetRlHatInvModrPrecon(index), cryptoParams->GetRlHatModq(index),
                                             cryptoParams->GetalphaRlModq(index), cryptoParams->GetModqBarrettMu(),
                                             cryptoParams->GetrInv());
#ifdef _OPENMP
        omp_set_nested(true);
#endif


        //ciphertext.SetFormat(Format::EVALUATION);
    //retValue.SetElements(std::move(ciphertexts));
//#ifdef _OPENMP
//    omp_set_nested(true);
//#endif
}

DCRTPoly SLAPScheme::Encrypt(const DCRTPoly & plaintext, const DCRTPoly & privateKey, const DCRTPoly& publicKey,
        const bool do_noise,
        double & noise_time, double & enc_time){
    DCRTPoly noisy_input = plaintext;
    if(do_noise){
        //noisy_input.add_dp_noise(this->dl, num, den);
        dl.addRandomNoise(noisy_input,scale, LAPLACIAN);
    }
    else{
        noise_time = 0.0;
    }
    //Now get key and do encryption
    DCRTPoly enc_result = (scheme==NS)? NSEncrypt(noisy_input, privateKey, publicKey) :
            MSEncrypt(noisy_input, privateKey, publicKey);
    return enc_result;
}

DCRTPoly SLAPScheme::NSEncrypt(const DCRTPoly &plaintext, const DCRTPoly &privateKey, const DCRTPoly& publicKey){
    //Multiply secret and public keys
    DCRTPoly ret = privateKey*publicKey;
    std::cout << "Encrypt key " << ret << std::endl;
    //Get the error, and scale it by the plaintext modulus
    DCRTPoly e = ciphertextParams.CloneParametersOnly();
    e.SetValuesToZero();
    //TODO replace this - taken out for debugging
    //e.error(this->dl);
    dl.addRandomNoise(e,3, UNIFORM);
    //e.zero();
    e.Times(t_mod_q); //Per-modulus scaling
    std::cout << "Error is " << e << std::endl;
    //Add in the error to make a RLWE term
    ret += e;
    //Raise x to base q
    DCRTPoly x_raised = plaintext.Clone();
    SwitchBasis(x_raised, ciphertextParams);
            //x.base_conv(ctext_parms, *t_to_q);
            DCRTPoly test = x_raised.Clone();
    SwitchBasis(test,plaintextParams);
    std::cout << " Basis result " << test << std::endl;
            //Now add the message
    ret += x_raised;
    return ret;
}

DCRTPoly SLAPScheme::MSEncrypt(const DCRTPoly &plaintext, const DCRTPoly& privateKey, const DCRTPoly& publicKey){
    //Multiply secret and public keys
    DCRTPoly ret = privateKey*publicKey;
    //Get the error, and scale it by the plaintext modulus
    DCRTPoly e = ciphertextParams.CloneParametersOnly();
    e.SetValuesToZero();
    //e.error(this->dl);
    dl.addRandomNoise(e,3, UNIFORM);

    std::cout << "Error is " << e << std::endl;
    //Add in the error to make a RLWE term
    ret += e;
    //Raise x to base q
    DCRTPoly x_raised = plaintext.Clone();
    SwitchBasis(x_raised, ciphertextParams);
    //DCRTPoly x_raised = ret.SwitchCRTBasis(something);
            //x.base_conv(ctext_parms, *t_to_q);
    //Scale x by delta
    x_raised.Times(delta_mod_q);
    //Now add the message
    ret += x_raised;
    return ret;
}

DCRTPoly SLAPScheme::Decrypt(const std::vector<DCRTPoly>& ciphertexts, const DCRTPoly& aggregationKey, const uint64_t ts,
                             double & dec_time, unsigned int num_additions){
    auto begin = std::chrono::steady_clock::now();
    DCRTPoly publicKey;
    PublicKey(publicKey, ts);
    DCRTPoly ret = (scheme == NS) ?
            NSDecrypt(ciphertexts, aggregationKey, publicKey, num_additions) : MSDecrypt(ciphertexts, aggregationKey, publicKey, num_additions);
    auto end = std::chrono::steady_clock::now();
    dec_time = std::chrono::duration_cast<time_typ>(end - begin).count();

    return ret;
}

DCRTPoly SLAPScheme::Decrypt(const std::vector<DCRTPoly>& ciphertexts, const DCRTPoly &aggregationKey, const DCRTPoly& publicKey,
                             double & dec_time, unsigned int num_additions){
    auto begin = std::chrono::steady_clock::now();
    DCRTPoly ret = (scheme == NS) ?
                   NSDecrypt(ciphertexts, aggregationKey, publicKey, num_additions) : MSDecrypt(ciphertexts, aggregationKey, publicKey, num_additions);
    auto end = std::chrono::steady_clock::now();
    dec_time = std::chrono::duration_cast<time_typ>(end - begin).count();
    return ret;
}

DCRTPoly SLAPScheme::NSDecrypt(const std::vector<DCRTPoly>& ciphertexts,const DCRTPoly &aggregationKey, const DCRTPoly &publicKey,
                               unsigned int num_additions){

    DCRTPoly ret = aggregationKey*publicKey;
    std::cout << "Decryption key result " << ret << std::endl;
    if(!num_additions){
        num_additions = ciphertexts.size();
    }

    for(unsigned int i = 0; i < num_additions; i++){
        ret += ciphertexts.at(i % ciphertexts.size());
    }
    auto end = std::chrono::steady_clock::now();
    //return ret.base_conv(plain_parms, *q_to_t);
    SwitchBasis(ret, plaintextParams);
    return ret;
}


//Set num_additions nonzero to control whether the size of ciphertexts is used to determine the number of iterations, or if a smaller array can be used
DCRTPoly SLAPScheme::MSDecrypt(const std::vector<DCRTPoly>& ciphertexts,const DCRTPoly& aggregationKey, const DCRTPoly& publicKey,
                               unsigned int num_additions){
    DCRTPoly ret = aggregationKey*publicKey;
    //Add all the ciphertexts (mod q)
    if(!num_additions){
        num_additions = ciphertexts.size();
    }

    for(unsigned int i = 0; i < num_additions; i++){
        ret += ciphertexts.at(i % ciphertexts.size());
    }
    auto end = std::chrono::steady_clock::now();
    //Now scale and reduce
    //return ret.scale_down(plain_parms, *q_to_t);
    //SwitchBasis(ret, plaintextParams);
    ScaleDown(ret,plaintextParams);
    return ret;
}

DCRTPoly SLAPScheme::PolynomialEncrypt(const std::vector<double>& plaintext,
                                       const DCRTPoly& privateKey, const DCRTPoly& publicKey,
                           bool do_noise, double & noise_time, double & enc_time, const uint64_t e){

    //First, add differentially private noise to x
    //No easy way around copying x while keeping input clean
    std::vector<double> noisy_input = plaintext;
    if(do_noise){
        //noisy_input.add_dpg_noise(this->dl, num, den);
        //dl.addRandomNoise(noisy_input,scale,);
        ppow(noisy_input,e);
        auto begin = std::chrono::steady_clock::now();
        dl.addRandomNoise(noisy_input,scale, LAPLACIAN);
        auto end = std::chrono::steady_clock::now();
        noise_time = std::chrono::duration_cast<time_typ>(end - begin).count();
    }
    else{
        noise_time = 0.0;
    }
    std::cout << "Noisy Input before log " << noisy_input << std::endl;
    //Now get key and do encryption
    //Now get key and do encryption
    auto begin = std::chrono::steady_clock::now();
    for (int i = 0; i < noisy_input.size(); i++){
        noisy_input.at(i) = log(noisy_input.at(i));
        //Ugly fix to prevent bad values from going into MakeCKKSPackedPlaintext
        if(!std::isfinite(noisy_input.at(i)) || std::isnan(noisy_input.at(i))){
            noisy_input.at(i) = 0;
        }
    }
    std::cout << "Noisy Input " << noisy_input << std::endl;
    DiscreteFourierTransform::Initialize(plaintextParams.GetRingDimension() * 2, plaintextParams.GetRingDimension() / 2);
    Plaintext ckks_result = CKKSContext->MakeCKKSPackedPlaintext(noisy_input, 2,1,plaintextParams.GetParams(),plaintextParams.GetRingDimension()/2);
    ckks_result->Encode();

    DCRTPoly poly_result = ckks_result->GetElement<DCRTPoly>();

    std::cout << "CCE Result:  " <<  poly_result << std::endl;
    //std::dynamic_pointer_cast<CKKSPackedEncoding>(ckks_result)->Decode(1,40,FIXEDAUTO,CKKSparameters.GetExecutionMode());
    std::vector<double> intermediate1 = ckks_result->GetRealPackedValue();
    std::cout << "CCE Decoding Result:  " << ckks_result->GetElement<DCRTPoly>() << std::endl;
    std::cout << "CCE Decoding Float Result:  " << intermediate1 << std::endl;

    DCRTPoly enc_result = (scheme==NS)? NSEncrypt(poly_result, privateKey, publicKey) :
                          MSEncrypt(poly_result, privateKey, publicKey);
    auto end = std::chrono::steady_clock::now();
    enc_time = std::chrono::duration_cast<time_typ>(end - begin).count();
    return enc_result;

};

std::vector<double> SLAPScheme::PolynomialDecrypt(const std::vector<DCRTPoly>& ciphertexts, const DCRTPoly& aggregationKey, const DCRTPoly& publicKey,
                                                  double & dec_time, unsigned int num_additions){

    auto begin = std::chrono::steady_clock::now();
    DCRTPoly ret = (scheme == NS) ?
                   NSDecrypt(ciphertexts, aggregationKey, publicKey, num_additions) : MSDecrypt(ciphertexts, aggregationKey, publicKey, num_additions);
    std::cout << "Here's the decrypted cyphertext from PSA " <<  ret << std::endl;
    Plaintext decrypted = CKKSContext->GetPlaintextForDecrypt(CKKS_PACKED_ENCODING,
                                                 ret.GetParams(), CKKSContext->GetEncodingParams());

    //decrypted->GetElement<DCRTPoly>() = ret;
    //Test(ret, &decrypted->GetElement<NativePoly>());
    //Test(ret, &decrypted->GetElement<NativePoly>());
    ret.SetFormat(COEFFICIENT);
    decrypted->GetElement<NativePoly>() = ret.ToNativePoly();
    //std::cout << decrypted->GetElement<NativePoly>() << std::endl;
    //*decrypted = ret.GetElementAtIndex(0);
    //*decrypted = Poly(ret.GetElementAtIndex(0), Format::EVALUATION);


    ///std::vector<std::complex<double>> complexValues;
    ////for (size_t i = 0; i < ret.GetLength(); ++i) {
    ////    complexValues.emplace_back(static_cast<double>(ret.GetElementAtIndex(0)[i].ConvertToDouble()), 0.0);
    ////}
    ////complexValues.resize(ret.GetNumOfElements());
    //std::cout << "poly.GetModulus().ConvertToInt() after ptxt: " << poly.GetModulus().ConvertToInt() << std::endl;

    ////Plaintext decrypted = CKKSContext->MakeCKKSPackedPlaintext(complexValues);

    auto decryptedCKKS = std::dynamic_pointer_cast<CKKSPackedEncoding>(decrypted);
    decryptedCKKS->SetNoiseScaleDeg(2); //2
    decryptedCKKS->SetLevel(1); // 1
    decryptedCKKS->SetScalingFactor(40); // 40
    decryptedCKKS->SetSlots(ret.GetRingDimension()/2); //which is the N/2
    //decryptedCKKS->GetEncodingParams()->SetPlaintextModulus(plaintextParams.GetModulus().ConvertToInt());


    //const auto cryptoParamsCKKS = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(CKKSContext->GetCryptoParameters());

    //Decode(*decryptedCKKS.get(),1, 40,
    //                      NORESCALE, EXEC_EVALUATION);

    //CKKSPackedEncoding float_result = CKKSPackedEncoding(cvec,0);
    decryptedCKKS->Decode(1,40,FIXEDAUTO,CKKSparameters.GetExecutionMode());

    //Plaintext plaintext;
    //plaintext = std::move(decrypted);
    //std::cout << "PLAINTEXT " << plaintext << std::endl;

    std::vector<double> intermediate1 = decryptedCKKS->GetRealPackedValue();

    std::cout << "Decrypted without exponentiation " << intermediate1 << std::endl;

    for (int i = 0; i < intermediate1.size(); i++){
        intermediate1.at(i) = exp(intermediate1.at(i));
    }

    auto end = std::chrono::steady_clock::now();
    dec_time = std::chrono::duration_cast<time_typ>(end - begin).count();
    return intermediate1;

}

std::vector<double> SLAPScheme::PolynomialDecrypt(const std::vector<DCRTPoly> &ciphertexts, const DCRTPoly& aggregationKey, const uint64_t ts,
                                                  double & dec_time, unsigned int num_additions){
    //high_resolution_clock::time_point start, end;
    //start = high_resolution_clock::now();
    DCRTPoly pk;
    PublicKey(pk,ts);
    //end = high_resolution_clock::now();
    //double tmp = duration_cast<chrono::nanoseconds>(end-start).count();
    std::vector<double> ret = PolynomialDecrypt(ciphertexts, aggregationKey, pk, dec_time, num_additions);
    //dec_time += tmp; //Assume public key can be precomputed - TODO actually make this a compiletime or runtime choice
    return ret;

}
