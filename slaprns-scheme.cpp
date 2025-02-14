//
// Created by Antonia Januszewicz on 3/27/24.
//

#include <chrono>

#include <omp.h>

#include "slaprns-scheme.h"
#include <omp.h>

using namespace lbcrypto;
using namespace std::chrono;

using time_typ = std::chrono::nanoseconds;

DCRTPoly SwitchMod(DCRTPoly input, const DCRTPoly outputMod) {
    /**
    auto m_values = input.GetValues();
    auto m_params = input.GetParams();
    if (m_values.GetLength() != 0) {
        m_values.SwitchModulus(outputMod.GetModulus());
        auto c{m_params->GetCyclotomicOrder()};
        m_params = outputMod.GetParams();
    }**/
    DCRTPoly output = outputMod.CloneParametersOnly();
    output.SetValuesModSwitch(input, outputMod.GetModulus());
    return output;
    /**
    DCRTPoly output = outputMod.CloneParametersOnly();
    std::cout << input.GetNumOfElements() << std::endl;
    for (int i = 0; i < input.GetNumOfElements(); i++){
        DCRTPoly intermediate = input.CloneParametersOnly();
        DCRTPoly intermediate2 = outputMod.CloneParametersOnly();
        intermediate.SetElementAtIndex(0,input.GetElementAtIndex(i));
        intermediate2.SetValuesModSwitch(intermediate, outputMod.GetModulus());
        output.SetElementAtIndex(i,intermediate2.GetElementAtIndex(0));

    }
    return output;
    DCRTPoly output = outputMod.CloneParametersOnly();
    auto in = input.GetElementAtIndex(0).GetParams();
    auto Q             = input.GetElementAtIndex(0).GetModulus();
    double Qmod_double = outputMod.GetModulus().ConvertToDouble() / Q.ConvertToDouble();
    output.GetParams()->SetOriginalModulus(outputMod.GetModulus());
    //auto input{input.GetElementAtIndex(0)};
    input.SetFormat(Format::COEFFICIENT);
    size_t size{input.GetValues().GetLength()};
    size_t N_elem(output.GetParams()->GetRingDimension());
    size_t N(input.GetRingDimension());
    for (size_t i = 0; i < size; ++i) {
        NativeVector tmp(N);
        tmp.SetModulus(outputMod.GetModulus());

        for (size_t j = 0; j < N_elem; ++j) {
            tmp[j] =
                    NativeInteger(static_cast<uint64_t>(std::floor(0.5 + input[j].ConvertToDouble() * Qmod_double))).Mod(outputMod.GetModulus());
        }

        //m_vectors[i].SetValues(std::move(tmp), Format::COEFFICIENT);
    }**/
}

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
    CKKSparameters.SetScalingModSize(10);
    //plaintextParams.GetModulus().GetLengthForBase(2)
    CKKSparameters.SetBatchSize(plaintextParams.GetRingDimension()/2);
    CKKSparameters.SetScalingTechnique(FIXEDAUTO);
    //CKKSparameters.SetPlaintextModulus(plaintextParams.GetModulus().ConvertToInt());
    CKKSContext = GenCryptoContext(CKKSparameters);
    CKKSContext->GetCryptoParameters()->SetElementParams(plaintextParams.GetParams());

    //std::cerr << std::endl;
    //std::cerr << "CKKS parameters :::::::: " << CKKSparameters << std::endl;
    //std::cerr << std::endl;

    //std::cerr << std::endl;
    //std::cerr << "Element parameters :::::::: " << *plaintextParams.GetParams() << std::endl;
    //std::cerr << std::endl;
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
    //size_t index = plaintext.GetNumOfElements()-1;
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
    //std::cout << "Encrypt key " << ret << std::endl;
    //Get the error, and scale it by the plaintext modulus
    DCRTPoly e = ciphertextParams.CloneParametersOnly();
    e.OverrideFormat(COEFFICIENT);
    e.SetValuesToZero();
    //TODO replace this - taken out for debugging
    //e.error(this->dl);
    dl.addRandomNoise(e,3, UNIFORM);
    //e.zero();
    e.Times(t_mod_q); //Per-modulus scaling
    //std::cout << "Error is " << e << std::endl;
    //Add in the error to make a RLWE term
    ret.SwitchFormat();
    ret.OverrideFormat(COEFFICIENT);
    ret += e;
    //ret.SwitchFormat();
    //ret.OverrideFormat(COEFFICIENT);
    //Raise x to base q
    //std::cout << "Here we see that " << plaintext.GetRingDimension() << " is greater than " << ciphertextParams.GetRingDimension() << std::endl;
    DCRTPoly clone = plaintext.Clone();
    clone.SwitchFormat();
    DCRTPoly x_raised = SwitchMod(clone,ciphertextParams);
    x_raised.OverrideFormat(COEFFICIENT);
    //SwitchMod(x_raised,ciphertextParams);
    //SwitchBasis(x_raised, ciphertextParams);
            //x.base_conv(ctext_parms, *t_to_q);
     //std::cout << "Before switch " << clone.GetFormat() << " " << clone << std::endl;
    //std::cout << " Basis result " << x_raised.GetFormat() << " " << x_raised << std::endl;
    //std::cout << "Here we see that " << plaintextParams.GetRingDimension() << " is greater than " << x_raised.GetRingDimension() << std::endl;
    //x_raised.SwitchFormat();
            //Now add the message
    ret += x_raised;
    //ret.SwitchFormat();
    return ret;
}

DCRTPoly SLAPScheme::MSEncrypt(const DCRTPoly &plaintext, const DCRTPoly& privateKey, const DCRTPoly& publicKey){
    //Multiply secret and public keys
    DCRTPoly ret = privateKey*publicKey;
    //Get the error, and scale it by the plaintext modulus
    DCRTPoly e = ciphertextParams.CloneParametersOnly();
    e.OverrideFormat(COEFFICIENT);
    e.SetValuesToZero();
    //e.error(this->dl);
    dl.addRandomNoise(e,3, UNIFORM);

    //std::cout << "Error is " << e << std::endl;
    //Add in the error to make a RLWE term
    ret.SwitchFormat();
    ret.OverrideFormat(COEFFICIENT);
    ret += e;
    //Raise x to base q
    DCRTPoly clone = plaintext.Clone();
    clone.SwitchFormat();
    DCRTPoly x_raised = SwitchMod(clone,ciphertextParams);
    x_raised.OverrideFormat(COEFFICIENT);
    //x_raised.SwitchFormat();
    //DCRTPoly x_raised = ret.SwitchCRTBasis(something);
            //x.base_conv(ctext_parms, *t_to_q);
    //Scale x by delta

    //std::cout << "Before switch " << clone.GetFormat() << " " << clone << std::endl;
    //std::cout << " Basis result " << x_raised.GetFormat() << " " << x_raised << std::endl;
    //Now add the message
    ret += x_raised;
    //ret.SwitchFormat();
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
    ret.SwitchFormat();
    ret.OverrideFormat(COEFFICIENT);
    //std::cout << "Decryption key result " << ret << std::endl;
    if(!num_additions){
        num_additions = ciphertexts.size();
    }

    for(unsigned int i = 0; i < num_additions; i++){
        ret += ciphertexts.at(i % ciphertexts.size());
    }
    //auto end = std::chrono::steady_clock::now();
    //return ret.base_conv(plain_parms, *q_to_t);
    //ret.SwitchFormat();
    //std::cout << "Before second switch " << ret.GetFormat() << " " << ret << std::endl;
    DCRTPoly ret2 = SwitchMod(ret,plaintextParams);
    //std::cout << "After second switch no mod" << ret2 << std::endl;
    //ret2.SwitchFormat();
    ret2.OverrideFormat(COEFFICIENT);
    //std::cout << "After second switch " << ret2.GetFormat() << " " << ret2 << std::endl;
    //SwitchBasis(ret, plaintextParams);
    return ret2;
}


//Set num_additions nonzero to control whether the size of ciphertexts is used to determine the number of iterations, or if a smaller array can be used
DCRTPoly SLAPScheme::MSDecrypt(const std::vector<DCRTPoly>& ciphertexts,const DCRTPoly& aggregationKey, const DCRTPoly& publicKey,
                               unsigned int num_additions){
    DCRTPoly ret = aggregationKey*publicKey;
    ret.SwitchFormat();
    ret.OverrideFormat(COEFFICIENT);
    //Add all the ciphertexts (mod q)
    if(!num_additions){
        num_additions = ciphertexts.size();
    }

    for(unsigned int i = 0; i < num_additions; i++){
        ret += ciphertexts.at(i % ciphertexts.size());
    }
    //auto end = std::chrono::steady_clock::now();
    //Now scale and reduce
    //return ret.scale_down(plain_parms, *q_to_t);
    //SwitchBasis(ret, plaintextParams);
    //std::cout << "Before second switch " << ret.GetFormat() << " " << ret << std::endl;
    //ScaleDown(ret,plaintextParams);
    ret.Times(scale_mod_t);
    DCRTPoly ret2 = SwitchMod(ret,plaintextParams);
    //std::cout << "After second switch " << ret2.GetFormat() << " " << ret2 << std::endl;
    //std::cout << "Return modulus is " << ret.GetModulus().ConvertToInt() << std::endl;
    return ret2;
}

DCRTPoly SLAPScheme::PolynomialEncrypt(const std::vector<double>& plaintext,
                                       const DCRTPoly& privateKey, const DCRTPoly& publicKey,
                           bool do_noise, double & noise_time, double & enc_time, const std::vector<double>& e) {

    //First, add differentially private noise to x
    //No easy way around copying x while keeping input clean
    std::vector<double> noisy_input = plaintext;
    if (do_noise) {
        //noisy_input.add_dpg_noise(this->dl, num, den);
        //dl.addRandomNoise(noisy_input,scale,);
        ppow(noisy_input, e);
        auto begin = std::chrono::steady_clock::now();
        dl.addRandomNoise(noisy_input, scale, LAPLACIAN);
        auto end = std::chrono::steady_clock::now();
        noise_time = std::chrono::duration_cast<time_typ>(end - begin).count();
        //std::cout << "Noise time " << noise_time << std::endl;
    } else {
        noise_time = 0.0;
    }
    //std::cout << "After ppow: " << noisy_input << std::endl;
    //std::cout << "Noisy Input before log " << noisy_input << std::endl;
    //Now get key and do encryption
    //Now get key and do encryption
    auto begin = std::chrono::steady_clock::now();
    for (unsigned int i = 0; i < noisy_input.size(); i++) {
        noisy_input.at(i) = log(noisy_input.at(i));
        //Ugly fix to prevent bad values from going into MakeCKKSPackedPlaintext
        if (!std::isfinite(noisy_input.at(i)) || std::isnan(noisy_input.at(i))) {
            noisy_input.at(i) = 0;
        }
    }
    //std::cout << "Noisy Input " << noisy_input << std::endl;

    //CKKSContext->GetEncodingParams()->SetPlaintextModulus(plaintextParams.GetModulus().ConvertToInt());
    //CKKSContext->GetElementParams()->SetOriginalModulus(plaintextParams.GetModulus());
    //CKKSContext->GetEncodingParams()->SetPlaintextRootOfUnity(plaintextParams.GetRootOfUnity());
    //CKKSContext->GetEncodingParams()->SetPlaintextModulus(plaintextParams.GetModulus().ConvertToInt());
    //CKKSContext->GetCryptoParameters()->SetPlaintextModulus(plaintextParams.GetModulus().ConvertToInt());
    //CKKSContext->GetCryptoParameters()->SetElementParams(plaintextParams.GetParams());
    DiscreteFourierTransform::Initialize(plaintextParams.GetRingDimension() * 2,
                                         plaintextParams.GetRingDimension() / 2);
    Plaintext ckks_result = CKKSContext->MakeCKKSPackedPlaintext(noisy_input);
    //ckks_result->Encode();

    DCRTPoly poly_result = ckks_result->GetElement<DCRTPoly>();
    //poly_result.SwitchFormat();
    //std::cout << "CCE Result:  " << poly_result.GetFormat() << " " <<  poly_result << std::endl;
    DCRTPoly enc_result = (scheme == NS) ? NSEncrypt(poly_result, privateKey, publicKey) :
                          MSEncrypt(poly_result, privateKey, publicKey);
    auto end = std::chrono::steady_clock::now();
    enc_time = std::chrono::duration_cast<time_typ>(end - begin).count();
    //std::cout << "Enc time " << enc_time << std::endl;
    return enc_result;
}

std::vector<double> SLAPScheme::PolynomialDecrypt(const std::vector<DCRTPoly>& ciphertexts, std::vector<double> &constants, const DCRTPoly& aggregationKey, const DCRTPoly& publicKey,
                                                  double & dec_time, unsigned int num_additions){

    //auto begin = std::chrono::steady_clock::now();
    DCRTPoly ret = (scheme == NS) ?
                   NSDecrypt(ciphertexts, aggregationKey, publicKey, num_additions) : MSDecrypt(ciphertexts, aggregationKey, publicKey, num_additions);
    //std::cout << "Here's the decrypted cyphertext from PSA " << ret.GetFormat() << " " <<  ret << std::endl;
    //DCRTPoly e = plaintextParams.CloneParametersOnly();
    //e.SetValuesToZero();
    //e.OverrideFormat(COEFFICIENT);
    //dl.addRandomNoise(e,3, LAPLACIAN);
    //ret += e;
    //TO-DO PUT THIS BACK
    Plaintext decrypted = CKKSContext->GetPlaintextForDecrypt(CKKS_PACKED_ENCODING,
                                                 ret.GetParams(), CKKSContext->GetEncodingParams());

    //decrypted->GetElement<DCRTPoly>() = ret;
    //Test(ret, &decrypted->GetElement<NativePoly>());
    //Test(ret, &decrypted->GetElement<NativePoly>());
    //ret.SwitchFormat();
    //std::cout << "Format before final switch " << ret.GetFormat() << std::endl;
    decrypted->GetElement<NativePoly>() = ret.GetElementAtIndex(0);
    //decrypted->GetElement<Poly>() = ret.CRTInterpolate();
    //decrypted->GetElement<NativePoly>() = ret.ToNativePoly();
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

    int scalingFactor = 10;
    auto decryptedCKKS = std::dynamic_pointer_cast<CKKSPackedEncoding>(decrypted);
    decryptedCKKS->SetNoiseScaleDeg(2); //2
    decryptedCKKS->SetLevel(1); // 1
    decryptedCKKS->SetScalingFactor(scalingFactor); // 40
    decryptedCKKS->SetSlots(ret.GetRingDimension()/2); //which is the N/2
    //decryptedCKKS->GetEncodingParams()->SetPlaintextModulus(plaintextParams.GetModulus().ConvertToInt());


    const auto cryptoParamsCKKS = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(CKKSContext->GetCryptoParameters());

    //double stdDev = getStdDev(*decryptedCKKS.get(),1, scalingFactor,
    //                          FIXEDAUTO, CKKSparameters.GetExecutionMode());
    //std::cout << "StdDev " << stdDev << std::endl;
    //std::vector<double> intermediate1 = Decode(*decryptedCKKS.get(),1, 40,
    //                      FIXEDAUTO, CKKSparameters.GetExecutionMode());
    //std::cout << *ret.GetParams() << std::endl;
    //CKKSPackedEncoding float_result = CKKSPackedEncoding(cvec,0);
    decryptedCKKS->Decode(1,scalingFactor,FIXEDAUTO,CKKSparameters.GetExecutionMode());

    //Plaintext plaintext;
    //plaintext = std::move(decrypted);
    //std::cout << "PLAINTEXT " << plaintext << std::endl;
    std::vector<double> intermediate1 = decryptedCKKS->GetRealPackedValue();

    //std::cout << "Decrypted without exponentiation " << intermediate1 << std::endl;

    for (unsigned int i = 0; i < intermediate1.size(); i++){
        intermediate1.at(i) = exp(intermediate1.at(i));
    }

    //std::cout << "Intermediate decryption: " << intermediate1 << std::endl;

    for (unsigned int i = 0; i < intermediate1.size(); i++){
        intermediate1[i] *= constants[i];
    }
    //auto end = std::chrono::steady_clock::now();
    //dec_time = std::chrono::duration_cast<time_typ>(end - begin).count();
    return intermediate1;

}

std::vector<double> SLAPScheme::PolynomialDecrypt(const std::vector<DCRTPoly> &ciphertexts, std::vector<double> &constants,const DCRTPoly& aggregationKey, const uint64_t ts,
                                                  double & dec_time, unsigned int num_additions){
    //high_resolution_clock::time_point start, end;
    //start = high_resolution_clock::now();
    DCRTPoly pk;
    PublicKey(pk,ts);
    //end = high_resolution_clock::now();
    //double tmp = duration_cast<chrono::nanoseconds>(end-start).count();
    std::vector<double> ret = PolynomialDecrypt(ciphertexts, constants, aggregationKey, pk, dec_time, num_additions);
    //dec_time += tmp; //Assume public key can be precomputed - TODO actually make this a compiletime or runtime choice
    return ret;

}
