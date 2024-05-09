//
// Created by Antonia Januszewicz on 4/16/24.
//
#ifndef OPENFHE_UTILS_H
#define OPENFHE_UTILS_H

#include "PSA-base-scheme.h"

using namespace lbcrypto;

// Function to calculate the Hamming weight
static unsigned int hammingWeight(unsigned int n) {
    unsigned int count = 0;
    while (n) {
        count += n & 1;
        n >>= 1;
    }
    return count;
}


static std::vector<double> Polynomial_to_double_encoding(const DCRTPoly & p){
    std::vector<double> ret;
    ret.resize(p.GetModulus().ConvertToInt());
    for(size_t i = 0; i < ret.size(); i++){
        ret[i] = p[i].ConvertToDouble();
    }
    return ret;
}

static DCRTPoly encoding_to_Polynomial(const Plaintext & vals, const DCRTPoly parms){
    DCRTPoly ret = parms.CloneParametersOnly();
    auto intermediate1 = vals->GetPackedValue();
    BigVector intermediate2(intermediate1.size(),parms.GetModulus());
    //Technically not the most efficient iteration order for cache coherency
    for(size_t i = 0; i < intermediate1.size(); i++){
        intermediate2 = (BigInteger(intermediate1[i]));
    }
    ret.SetValues(intermediate2, EVALUATION);
    return ret;
}

static void ppow(DCRTPoly & rop, const  DCRTPoly& a, const uint64_t exp) {
    auto values = a.GetAllElements();
    BigVector ans(values.size(), 5);

    std::vector<int> mods;
    mods.reserve(a.GetParams()->GetParams().size());
    for (auto& p : a.GetParams()->GetParams())
        mods.emplace_back(p->GetModulus().ConvertToInt());

    for(size_t mod_idx = 0; mod_idx < mods.size(); mod_idx++) {
        uint64_t modulus = mods[mod_idx];
        auto temp = values[mod_idx].GetValues();
        for (size_t coeff_idx = 0; coeff_idx < temp.GetLength(); coeff_idx++) {
            uint128_t tmp = pow(temp[coeff_idx].ConvertToInt(), exp);
            //a.at(coeff_idx).ConvertToInt()
            tmp %= modulus;
            values[mod_idx].at(coeff_idx) = tmp;
        }
        rop.SetElementAtIndex(mod_idx, values[mod_idx]);

    }
}

static void ppow(std::vector<double> & noisy_input,const uint64_t e) {
    for(size_t mod_idx = 0; mod_idx < noisy_input.size(); mod_idx++) {
        noisy_input.at(mod_idx) = pow(noisy_input.at(mod_idx),e);
    }
}

static size_t choose_parameters(unsigned int required_q) {
    size_t n;
        //Ok
        if (required_q <= 27) {n = 1 << 10;}
            //This is the problematic one
        else if (required_q <= 54) {n = 1 << 11;}
            //Ok
        else if (required_q <= 109) {n = 1 << 12;}
            //Ok
        else if (required_q <= 218) { n = 1 << 13;}
            //Also problematic
        else if (required_q <= 438) { n = 1 << 14;}
            //Also problematic
        else if (required_q <= 881) { n = 1 << 15;}
        else {n = 0;}
        return n;
    }

    static size_t numTowers(unsigned int required_q){
    if (required_q < 27){
        return 1;
    }
    else if (required_q < 54){
        return 1;
    }
    else if (required_q < 109){
        return 3;
    }
    else if (required_q < 218){
        return 5;
    }
    else if(required_q <= 438) {
        return 16;
    }
    else {
        return 0;
    }
}
/**
template <typename P>
inline static void encodeVec(P& poly, const PlaintextModulus& mod, int64_t lb, int64_t ub,
                             const std::vector<int64_t>& value, SCHEME schemeID) {
    if (ub > INT32_MAX || lb < INT32_MIN)
        OPENFHE_THROW(config_error, "Cannot encode a coefficient larger than 32 bits");

    poly.SetValuesToZero();
    for (size_t i = 0; i < value.size() && i < poly.GetLength(); i++) {
        if (value[i] <= lb || value[i] > ub)
            OPENFHE_THROW(config_error, "Cannot encode integer " + std::to_string(value[i]) + " at position " +
                                        std::to_string(i) + " because it is out of range of plaintext modulus " +
                                        std::to_string(mod));

        typename P::Integer entry{value[i]};

        if (value[i] < 0) {
            if (schemeID == SCHEME::BFVRNS_SCHEME) {
                // TODO: Investigate why this doesn't work with q instead of t.
                uint64_t adjustedVal{mod - static_cast<uint64_t>(llabs(value[i]))};
                entry = typename P::Integer(adjustedVal);
            }
            else {
                // It is more efficient to encode negative numbers using the ciphertext
                // modulus no noise growth occurs
                entry = poly.GetModulus() - typename P::Integer(static_cast<uint64_t>(llabs(value[i])));
            }
        }
        auto test = poly[i];
        std::cout << poly[i] << std::endl;
        poly[i] = entry;
    }
}


DCRTPolyImpl<BigVector> static SwitchCRTBasis1(const DCRTPoly & paramsP,
                                                            const std::vector<NativeInteger>& QHatInvModq,
                                                            const std::vector<NativeInteger>& QHatInvModqPrecon,
                                                            const std::vector<std::vector<NativeInteger>>& QHatModp,
                                                            const std::vector<std::vector<NativeInteger>>& alphaQModp,
                                                            const std::vector<DoubleNativeInt>& modpBarrettMu,
                                                            const std::vector<double>& qInv, DCRTPoly & input) {
#if defined(HAVE_INT128) && NATIVEINT == 64
    DCRTPolyImpl<BigVector> ans(paramsP.GetParams(), Format::COEFFICIENT, true);
    //(paramsP, input.GetFormat(), true);
    usint ringDim = input.GetParams()->GetRingDimension();
    //if (input.GetParams()->GetRingDimension() < paramsP.GetParams()->GetRingDimension()) {
    //    ringDim = input.GetParams()->GetRingDimension();
    //}
    //else {
    //    ringDim = paramsP.GetParams()->GetRingDimension();
    //}
    auto m_vectors = input.GetAllElements();
    auto ans_m_vectors = ans.GetAllElements();
    usint sizeQ   = m_vectors.size();
    usint sizeP   = ans_m_vectors.size();

//#pragma omp parallel for
    for (usint ri = 0; ri < ringDim; ri++) {
        //std::cout << "sizeQ " << sizeQ << std::endl;
        std::vector<NativeInteger> xQHatInvModq(sizeQ);
        //xQHatInvModq.reserve(sizeQ);
        double nu{0.5};

        // Compute alpha and vector of x_i terms
        for (usint i = 0; i < sizeQ; i++) {
            const NativeInteger& qi = m_vectors[i].GetModulus();
            // computes [x_i (Q/q_i)^{-1}]_{q_i}
            xQHatInvModq[i] = m_vectors[i][ri].ModMulFastConst(QHatInvModq[i], qi, QHatInvModqPrecon[i]);
            //std::cout << "The thing " << xQHatInvModq[i] << std::endl;
            // computes [x_i (Q/q_i)^{-1}]_{q_i} / q_i
            // to keep track of the number of q-overflows
            nu += xQHatInvModq[i].ConvertToDouble() * qInv[i];
        }

        // alpha corresponds to the number of overflows, 0 <= alpha <= sizeQ
        usint alpha = static_cast<usint>(nu);

        const std::vector<NativeInteger>& alphaQModpri = alphaQModp[alpha];

        for (usint j = 0; j < sizeP; j++) {
            DoubleNativeInt curValue = 0;

            const NativeInteger& pj                     = ans_m_vectors[j].GetModulus();
            const std::vector<NativeInteger>& QHatModpj = QHatModp[j];
            // first round - compute "fast conversion"
            for (usint i = 0; i < sizeQ; i++) {
                //std::cout << "In the loop xQHatInvModq " << xQHatInvModq[i] << std::endl;
                //std::cout << "In the loop QHatModpj" << QHatModpj[i] << std::endl;
                curValue += Mul128(xQHatInvModq[i].ConvertToInt(), QHatModpj[i].ConvertToInt());
            }

            const NativeInteger& curNativeValue =
                    NativeInteger(BarrettUint128ModUint64(curValue, pj.ConvertToInt(), modpBarrettMu[j]));

            // second round - remove q-overflows
            ans_m_vectors[j][ri] = curNativeValue.ModSubFast(alphaQModpri[j], pj);
        }
    }

    return ans;
}

#else
#pragma omp parallel for
    for (usint ri = 0; ri < ringDim; ++ri) {
        double nu = 0.5;
        for (size_t i = 0; i < sizeI; ++i) {
            // possible loss of precision if modulus greater than 2^53 + 1
            const NativeInteger& xi = m_vectors[i + inputIndex][ri];
            nu += tOSHatInvModsDivsFrac[i] * xi.ConvertToDouble();
        }
        if (isConvertableToNativeInt(nu)) {
            NativeInteger alpha = static_cast<BasicInteger>(nu);
            for (size_t j = 0; j < sizeO; j++) {
                const auto& tOSHatInvModsDivsModoj = tOSHatInvModsDivsModo[j];
                const auto& oj                     = ans.m_vectors[j].GetModulus();
                auto& curValue                     = ans.m_vectors[j][ri];
                for (size_t i = 0; i < sizeI; i++) {
                    const auto& xi = m_vectors[i + inputIndex][ri];
                    curValue.ModAddFastEq(xi.ModMulFast(tOSHatInvModsDivsModoj[i], oj, mu[j]), oj);
                }
                const auto& xi = m_vectors[outputIndex + j][ri];
                curValue.ModAddFastEq(xi.ModMulFast(tOSHatInvModsDivsModoj[sizeI], oj, mu[j]), oj);
                curValue.ModAddFastEq(alpha >= oj ? alpha.Mod(oj, mu[j]) : alpha, oj);
            }
        }
        else {
            int exp;
            double mant            = std::frexp(nu, &exp);
            NativeInteger mantissa = static_cast<BasicInteger>(mant * (1ULL << 53));
            NativeInteger exponent = static_cast<BasicInteger>(1ULL << (exp - 53));
            for (size_t j = 0; j < sizeO; j++) {
                const auto& tOSHatInvModsDivsModoj = tOSHatInvModsDivsModo[j];
                const auto& oj                     = ans.m_vectors[j].GetModulus();
                auto& curValue                     = ans.m_vectors[j][ri];
                for (size_t i = 0; i < sizeI; i++) {
                    const auto& xi = m_vectors[i + inputIndex][ri];
                    curValue.ModAddFastEq(xi.ModMulFast(tOSHatInvModsDivsModoj[i], oj, mu[j]), oj);
                }
                const auto& xi = m_vectors[outputIndex + j][ri];
                curValue.ModAddFastEq(xi.ModMulFast(tOSHatInvModsDivsModoj[sizeI], oj, mu[j]), oj);
                curValue.ModAddFastEq(exponent.ModMul(mantissa, oj, mu[j]), oj);
            }
        }
    }
    return ans;
}
#endif

std::vector<std::complex<double>> static Conjugate2(const std::vector<std::complex<double>>& vec) {
    uint32_t n = vec.size();
    std::vector<std::complex<double>> result(n);
    for (size_t i = 1; i < n; i++) {
        result[i] = {-vec[n - i].imag(), -vec[n - i].real()};
    }
    result[0] = {vec[0].real(), -vec[0].imag()};
    return result;
}

double static StdDev2(const std::vector<std::complex<double>>& vec, const std::vector<std::complex<double>>& conjugate) {
    uint32_t slots = vec.size();
    if (1 == slots) {
        return vec[0].imag();
    }
    // ring dimension
    uint32_t dslots = slots * 2;

    // extract the complex part using identity z - Conj(z) == 2*Im(z)
    // here we actually compute m(X) - m(1/X) corresponding to 2*Im(z).
    // we only need first Nh/2 + 1 components of the imaginary part
    // as the remaining Nh/2 - 1 components have a symmetry
    // w.r.t. components from 1 to Nh/2 - 1
    std::vector<std::complex<double>> complexValues(slots / 2 + 1);
    for (size_t i = 0; i < slots / 2 + 1; ++i) {
        complexValues[i] = vec[i] - conjugate[i];
    }

    // Calculate the mean
    auto mean_func = [](double accumulator, const std::complex<double>& val) {
        return accumulator + (val.real() + val.imag());
    };

    // use the symmetry condition
    double mean = 2 * std::accumulate(complexValues.begin() + 1, complexValues.begin() + slots / 2, 0.0, mean_func);
    // and then add values at indices 0 and Nh/2
    mean += complexValues[0].imag();
    mean += 2 * complexValues[slots / 2].real();
    // exclude the real part at index 0 as it is always 0
    mean /= static_cast<double>(dslots) - 1.0;

    // Now calculate the variance
    auto variance_func = [&mean](double accumulator, const std::complex<double>& val) {
        return accumulator + (val.real() - mean) * (val.real() - mean) + (val.imag() - mean) * (val.imag() - mean);
    };

    // use the symmetry condition
    double variance = 2 * accumulate(complexValues.begin() + 1, complexValues.begin() + slots / 2, 0.0, variance_func);
    // and then add values at indices 0 and Nh/2
    variance += (complexValues[0].imag() - mean) * (complexValues[0].imag() - mean);
    variance += 2 * (complexValues[slots / 2].real() - mean) * (complexValues[slots / 2].real() - mean);
    // exclude the real part at index 0 as it is always 0
    variance /= static_cast<double>(dslots) - 2.0;
    // scale down by 2 as we have worked with 2*Im(z) up to this point
    double stddev = 0.5 * std::sqrt(variance);

    return stddev;
}

bool static Decode(CKKSPackedEncoding & encoding, size_t noiseScaleDeg, double scalingFactor, ScalingTechnique scalTech,
                                ExecutionMode executionMode) {
    double p       = encoding.GetEncodingParams()->GetPlaintextModulus();
    double powP    = 0.0;
    uint32_t Nh    = encoding.GetElementRingDimension() / 2;
    uint32_t slots = encoding.GetSlots();
    uint32_t gap   = Nh / slots;
    //value.clear();
    std::vector<std::complex<double>> curValues(slots);

    if (true) {
        if (scalTech == FLEXIBLEAUTO || scalTech == FLEXIBLEAUTOEXT)
            powP = pow(scalingFactor, -1);
        else
            powP = pow(2, -p);

        const NativeInteger& q = encoding.GetElementModulus().ConvertToInt();
        NativeInteger qHalf    = q >> 1;

        for (size_t i = 0, idx = 0; i < slots; ++i, idx += gap) {
            std::complex<double> cur;

            if (encoding.GetElement<NativePoly>()[idx] > qHalf)
                cur.real(-((q - encoding.GetElement<NativePoly>()[idx])).ConvertToDouble());
            else
                cur.real((encoding.GetElement<NativePoly>()[idx]).ConvertToDouble());

            if (encoding.GetElement<NativePoly>()[idx + Nh] > qHalf)
                cur.imag(-((q - encoding.GetElement<NativePoly>()[idx + Nh])).ConvertToDouble());
            else
                cur.imag((encoding.GetElement<NativePoly>()[idx + Nh]).ConvertToDouble());

            curValues[i] = cur;
        }
    }
    else {
        powP = pow(2, -p);

        // we will bring down the scaling factor to 2^p
        double scalingFactorPre = 0.0;
        if (scalTech == FLEXIBLEAUTO || scalTech == FLEXIBLEAUTOEXT)
            scalingFactorPre = pow(scalingFactor, -1) * pow(2, p);
        else
            scalingFactorPre = pow(2, -p * (noiseScaleDeg - 1));

        const BigInteger& q = encoding.GetElementModulus();
        BigInteger qHalf    = q >> 1;

        for (size_t i = 0, idx = 0; i < slots; ++i, idx += gap) {
            std::complex<double> cur;

            if (encoding.GetElement<Poly>()[idx] > qHalf)
                cur.real(-((q - encoding.GetElement<Poly>()[idx])).ConvertToDouble() * scalingFactorPre);
            else
                cur.real((encoding.GetElement<Poly>()[idx]).ConvertToDouble() * scalingFactorPre);

            if (encoding.GetElement<Poly>()[idx + Nh] > qHalf)
                cur.imag(-((q - encoding.GetElement<Poly>()[idx + Nh])).ConvertToDouble() * scalingFactorPre);
            else
                cur.imag((encoding.GetElement<Poly>()[idx + Nh]).ConvertToDouble() * scalingFactorPre);

            curValues[i] = cur;
        }
    }

    // the code below adds a Gaussian noise to the decrypted result
    // to prevent key recovery attacks.
    // The standard deviation of the Gaussian noise is sqrt(M+1)*stddev,
    // where stddev is the standard deviation estimated using the imaginary
    // component and M is the extra factor that increases the number of decryption
    // attacks that is needed to average out the added Gaussian noise (after the
    // noise is removed, the attacker still has to find the secret key using the
    // real part only, which requires another attack). By default (M = 1), stddev
    // requires at least 128 decryption queries (in practice the values are
    // typically closer to 10,000 or so). Then M can be used to increase this
    // number further by M^2 (as desired for a given application). By default we
    // we set M to 1.

    // compute m(1/X) corresponding to Conj(z), where z is the decoded vector
    auto conjugate = Conjugate2(curValues);

    // Estimate standard deviation from 1/2 (m(X) - m(1/x)),
    // which corresponds to Im(z)
    double stddev = StdDev2(curValues, conjugate);

    double logstd = std::log2(stddev);

    if (executionMode == EXEC_NOISE_ESTIMATION) {
        //m_logError = logstd;
    }
    else {
        // if stddev < sqrt{N}/8 (minimum approximation error that can be achieved)
        if (stddev < 0.125 * std::sqrt(encoding.GetElementRingDimension())) {
            stddev = 0.125 * std::sqrt(encoding.GetElementRingDimension());
        }

        // if stddev < sqrt{N}/4 (minimum approximation error that can be achieved)
        // if (stddev < 0.125 * std::sqrt(GetElementRingDimension())) {
        //   if (noiseScaleDeg <= 1) {
        //    OPENFHE_THROW(math_error,
        //                   "The decryption failed because the approximation error is
        //                   " "too small. Check the protocol used. ");
        //  } else {  // noiseScaleDeg > 1 and no rescaling operations have been applied yet
        //    stddev = 0.125 * std::sqrt(GetElementRingDimension());
        //  }
        // }

        //   If less than 5 bits of precision is observed
        if (logstd > p - 5.0)
            OPENFHE_THROW(math_error,
                          "The decryption failed because the approximation error is "
                          "too high. Check the parameters. ");

        // real values
        std::vector<std::complex<double>> realValues(slots);

        // CKKS_M_FACTOR is a compile-level parameter
        // set to 1 by default
        stddev = sqrt(CKKS_M_FACTOR + 1) * stddev;

        double scale = 0.5 * powP;

        // TODO temporary removed errors
        std::normal_distribution<> d(0, stddev);
        PRNG& g = PseudoRandomNumberGenerator::GetPRNG();
        // Alternative way to do Gaussian sampling
        // DiscreteGaussianGenerator dgg;

        // TODO we can sample Nh integers instead of 2*Nh
        // We would add sampling only for even indices of i.
        // This change should be done together with the one below.
        for (size_t i = 0; i < slots; ++i) {
            double real = scale * (curValues[i].real() + conjugate[i].real());
            // real += powP * dgg.GenerateIntegerKarney(0.0, stddev);
            real += powP * d(g);
            double imag = scale * (curValues[i].imag() + conjugate[i].imag());
            // imag += powP * dgg.GenerateIntegerKarney(0.0, stddev);
            imag += powP * d(g);
            realValues[i].real(real);
            realValues[i].imag(imag);
        }

        // TODO we can half the dimension for the FFT by decoding in
        // Z[X + 1/X]/(X^n + 1). This would change the complexity from n*logn to
        // roughly (n/2)*log(n/2). This change should be done together with the one
        // above.
        DiscreteFourierTransform::FFTSpecial(realValues, encoding.GetElementRingDimension() * 2);

        // clears all imaginary values for security reasons
        for (size_t i = 0; i < realValues.size(); ++i)
            realValues[i].imag(0.0);

        // sets an estimate of the approximation error
        //m_logError = std::round(std::log2(stddev * std::sqrt(2 * slots)));

        //TODO
        //return realValues;
    }

    return false;
}
**/
void static Test(DCRTPoly & ciphertext,
        NativePoly* plaintext){
    *plaintext = ciphertext.GetElementAtIndex(0);
}


#endif