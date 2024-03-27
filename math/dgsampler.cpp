#include "dgsampler.h"
#include <iostream>

int main() {
    std::random_device rd;
    std::mt19937 rng(rd());

    // Example usage
    double sigma2 = 10;
    int sample = sample_dgauss(sigma2, rng);
    std::cout << "Sample from discrete Gaussian with sigma^2 = " << sigma2 << ": " << sample << std::endl;

    return 0;
}
