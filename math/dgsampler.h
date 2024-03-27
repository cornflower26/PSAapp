#include <iostream>
#include <random>
#include <cmath>

// Sample uniformly from range [0, m)
int sample_uniform(int m, std::mt19937& rng) {
    std::uniform_int_distribution<int> dist(0, m - 1);
    return dist(rng);
}

// Sample from a Bernoulli(p) distribution
int sample_bernoulli(double p, std::mt19937& rng) {
    std::bernoulli_distribution dist(p);
    return dist(rng);
}

// Sample from a Bernoulli(exp(-x)) distribution
int sample_bernoulli_exp(double x, std::mt19937& rng) {
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
int sample_geometric_exp(double x, std::mt19937& rng) {
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
int sample_dlaplace(double scale, std::mt19937& rng) {
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
int sample_dgauss(double sigma2, std::mt19937& rng) {
    int t = floorsqrt(sigma2) + 1;
    while (true) {
        int candidate = sample_dlaplace(t, rng);
        double bias = pow(abs(candidate) - sigma2 / t, 2) / (2 * sigma2);
        if (sample_bernoulli(exp(-bias), rng) == 1) {
            return candidate;
        }
    }
}
