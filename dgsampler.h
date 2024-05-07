#ifndef OPENFHE_DGSAMPLER_H
#define OPENFHE_DGSAMPLER_H

#include <iostream>
#include <random>
#include <cmath>
#include <core/lattice/lat-hal.h>

using namespace lbcrypto;

class DiscreteLaplacianGenerator {
public:

// Sample uniformly from range [0, m)
    int sample_uniform(int m, std::mt19937 &rng) {
        std::uniform_int_distribution<int> dist(0, m - 1);
        return dist(rng);
    }

    int u(const double scale){
        std::random_device rd;
        std::mt19937 rng(rd());
        return sample_uniform(scale, rng);
    }

    void uniform(DCRTPoly input){
        for(size_t j = 0; j < input.GetNumOfElements(); j++){
            uint64_t qi = input.GetElementAtIndex(j).GetModulus().ConvertToInt();
            auto element = input.GetElementAtIndex(j).GetValues();
            input.GetElementAtIndex(j).Plus(u(qi));
        }
    }


// Sample from a Bernoulli(p) distribution
    int sample_bernoulli(double p, std::mt19937 &rng) {
        std::bernoulli_distribution dist(p);
        return dist(rng);
    }

// Sample from a Bernoulli(exp(-x)) distribution
    int sample_bernoulli_exp(double x, std::mt19937 &rng) {
        int k = 1;
        while (true) {
            if (sample_bernoulli(exp(-x / k), rng) == 1) {
                k++;
            } else {
                break;
            }
        }
        return k % 2;
    }

// Sample from a geometric(1-exp(-x)) distribution
    int sample_geometric_exp(double x, std::mt19937 &rng) {
        int k = 0;
        while (true) {
            if (sample_bernoulli_exp(x, rng) == 1) {
                k++;
            } else {
                return k;
            }
        }
    }

// Sample from a discrete Laplace(scale) distribution
    int sample_dlaplace(double scale, std::mt19937 &rng) {
        std::geometric_distribution<int> geom_dist(0.5);
        std::uniform_real_distribution<double> uni_dist(0.0, 1.0);

        while (true) {
            int sign = sample_bernoulli(0.5, rng);
            int magnitude = geom_dist(rng);
            if (sign == 1 && magnitude == 0) {
                continue;
            }
            return magnitude * (1 - 2 * sign);
        }
    }

// Compute floor(sqrt(x)) exactly
    int floorsqrt(int x) {
        int a = 0;
        int b = 1;
        while (b * b <= x) {
            b *= 2;
        }
        while (a + 1 < b) {
            int c = (a + b) / 2;
            if (c * c <= x) {
                a = c;
            } else {
                b = c;
            }
        }
        return a;
    }

// Sample from a discrete Gaussian distribution N_Z(0,sigma2)
    int sample_dgauss(double sigma2, std::mt19937 &rng) {
        int t = floorsqrt(sigma2) + 1;
        while (true) {
            int candidate = sample_dlaplace(t, rng);
            double bias = pow(abs(candidate) - sigma2 / t, 2) / (2 * sigma2);
            if (sample_bernoulli(exp(-bias), rng) == 1) {
                return candidate;
            }
        }
    }

    int dg(const double scale){
        std::random_device rd;
        std::mt19937 rng(rd());
        return sample_dgauss(scale, rng);
    }

    void addGaussianNoise(std::vector<double> &input, const double scale){
        for (size_t i = 0; i < input.size(); i++){
            input.at(i) += dg(scale);
        }
    }


    const static unsigned int CONV_ITERS = 1000;
    constexpr const static float ERROR = 1e-5;

    //The actual function to sample from the discrete Laplacian distribution
    const static int BETA_SCALE = 1000;
    int dl(const double scale){
        std::random_device rd;
        std::mt19937 rng(rd());
        int beta_prob = sample_uniform(BETA_SCALE, rng);
        if(beta_prob <= 0){
            return sample_dlaplace(scale, rng);
        }
        else{
            return 0;
        }
    }

    void addRandomNoise(DCRTPoly &input, const double scale, const Distribution dist){

        DCRTPoly res(input.GetParams(), input.GetFormat());
        auto c{input.GetParams()->GetCyclotomicOrder()};
        const auto& m{input.GetParams()->GetModulus()};
        auto parm{std::make_shared<ILParamsImpl<BigInteger>>(c, m, 1)};
        DCRTPolyImpl<BigVector>::PolyLargeType element(parm);
        element.SetValues(GenerateVector(c/2,scale, m,dist), input.GetFormat());
        input = element;

        //input.Plus(GenerateVector(c/2,scale, m,dist));

        //input.Plus(GenerateVector(input.GetNumOfElements(),c / 2, m,dist));

        //DCRTPoly output(input.GetParams());
        //std::vector<std::complex<double>> randomIntVector;
        //output.SetValuesToZero();
        //for (size_t i = 0; i < input.GetNumOfElements(); i++){
        //    randomIntVector.push_back(dl(scale));
        //}
        //output.SetValues(GenerateVector(input.GetNumOfElements(), scale, input.GetModulus(), dist), COEFFICIENT);
        //input += output;
    }

    void addRandomNoise(std::vector<double> &input, const double scale, const Distribution dist){
        for (size_t i = 0; i < input.size(); i++){
            if (dist == LAPLACIAN){
                input.at(i) += dl(scale);
            }
            else if (dist == GAUSS){
                input.at(i) += dg(scale);
            }
            else if (dist == UNIFORM){
                input.at(i) += u(scale);
            }
        }
    }

    //discretegaussiangenerator-impl.h
    BigVector GenerateVector(const usint size, const double scale,
                           const typename BigVector::Integer& modulus, const Distribution dist) {
        auto result = GenerateIntVector(size, scale, dist);
        BigVector ans(size, modulus);
        for (usint i = 0; i < size; i++) {
            int32_t v = (result.get())[i];
            if (v < 0)
                ans[i] = modulus - typename BigVector::Integer(-v);
            else
                ans[i] = typename BigVector::Integer(v);
        }
        return ans;
    }

    std::shared_ptr<int64_t> GenerateIntVector(usint size, const double scale, const Distribution dist) {
        std::shared_ptr<int64_t> ans(new int64_t[size], std::default_delete<int64_t[]>());
        for (usint i = 0; i < size; ++i) {
            int64_t val;
            if (dist == LAPLACIAN){
                val = dl(scale);
            }
            else if (dist == GAUSS){
                val = dg(scale);
            }
            else if (dist == UNIFORM){
                val = u(scale);
            }
            (ans.get())[i] = val;
        }
        return ans;
    }


};

#endif  //OPENFHE_DGSAMPLER_H