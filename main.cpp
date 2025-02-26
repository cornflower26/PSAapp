//#include <core/lattice/lat-hal.h>
//#include <pke/openfhe.h>
#include <iostream>
#include <getopt.h>
#include <execinfo.h>
#include <signal.h>
#include <unistd.h>
#include <math/dftransform.h>
#include "PSA-cryptocontext.h"
#include <vector>
#include <fstream>
#include <sstream>
#include <cmath>
#include <algorithm>

using namespace std;

// Constants
const double C = 1.0; // Regularization parameter
const double tol = 1e-3; // Tolerance for errors
const double eps = 1e-3; // Small value for numerical comparisons

// Global variables
vector<vector<double>> points; // Training points
vector<int> target; // Labels (+1, -1)
vector<double> alpha; // Lagrange multipliers
vector<double> w; // Weight vector (for linear SVM)
double b = 0.0; // Bias
int numChanged; // Number of changes in each iteration

// Linear kernel
double kernel(const vector<double>& x1, const vector<double>& x2) {
    double result = 0.0;
    for (size_t i = 0; i < x1.size(); i++)
        result += x1[i] * x2[i];
    return result;
}

void handler(int sig) {
    void *array[10];
    size_t size;

    // get void*'s for all entries on the stack
    size = backtrace(array, 10);

    // print out all the frames to stderr
    fprintf(stderr, "Error: signal %d:\n", sig);
    backtrace_symbols_fd(array, size, STDERR_FILENO);
    exit(1);
}

double slap(int argc, char **argv, std::vector<std::vector<double>>& inputmatrix) {
    signal(SIGSEGV, handler);
    std::cout << "Hello, World! " << std::endl;
    //DCRTPoly a = DCRTPoly();
    unsigned int plain_bits = 15; //log t
    unsigned int num_users = 6; //n
    unsigned int iters = 1; //i
    unsigned int k_prime = 1; //k
    Scheme scheme1 = NS;

    unsigned int N = 1; //N

    int c;
    while((c = getopt(argc, argv, "t:n:i:k:N:")) != -1){
        switch(c){
            case 't':{
                plain_bits = atoi(optarg);
                break;
            }
            case 'n':{
                num_users = atoi(optarg);
                break;
            }
            case 'i':{
                iters = atoi(optarg);
                break;
            }
            case 'k':{
                k_prime = atoi(optarg);
                break;
            }
            case 'N':{
                N = atoi(optarg);
                break;
            }
            default:{
                std::cout << "Invalid argument: " << c;
                if(optarg != nullptr){
                    std::cout << ' ' << optarg;
                }
                std::cout << std::endl;
                return 1;
            }
        }
    }

    if(!plain_bits){
        throw std::runtime_error("Must have nonempty plaintext space");
    }
    if(!num_users){
        throw std::runtime_error("Must have at least some users");
    }
    if(!iters){
        throw std::runtime_error("Must have at least some iterations");
    }

    unsigned int MAX_CTEXTS_DEFAULT = 20;

    PSACryptocontext pp = PSACryptocontext(plain_bits, num_users, iters, scheme1);

    std::vector<double> poly_noise_times;
    std::vector<double> poly_enc_times;

    //pp.TestPolynomialEncryption(true, iters, poly_noise_times, poly_enc_times);
    // pp.TestPolynomialEncryption(1, MAX_CTEXTS_DEFAULT, poly_noise_times, poly_enc_times);

    pp.PolynomialEnvSetup(poly_noise_times, poly_enc_times);

    std::vector<double> expvec(inputmatrix[0].size(), 1);

    for (int i = 0; i < num_users; i++) {
        //std::cout << i << " input: " << inputmatrix[i] << std::endl;
        pp.PolynomialEncryption(inputmatrix[i], expvec, i, poly_noise_times, poly_enc_times);
    }

    std::vector<double> decrypt_times;

    std::vector<double> constants(num_users, 1);
    std::vector<double> outputvec = pp.PolynomialDecryption(constants, 1, decrypt_times);

    std::cout << "Final output: " << outputvec << std::endl;

    for(const double d : poly_noise_times){
        //std::cout << "poly_noise_times " << d << '\n';
    }
    for(const double d : poly_enc_times){
        //std::cout << "poly_enc_times " << d << '\n';
    }
    for(const double d : decrypt_times){
        //std::cout << "decrypt_times " << d << '\n';
    }

    double sum = std::accumulate(outputvec.begin(), outputvec.end(), 0);

    return sum;
}

double SVMOutputonpoint(int argc, char **argv, int k){
    double u = kernel(w, points[k]) - b;
    return u;
}

// SVM output for a given point
double objectiveFunction(int argc, char **argv, std::vector<double>& alphavec, std::vector<int>& targetvec, std::vector<std::vector<double>>& pointsvec) {

    size_t n_size = 15; // So that the vector size is 15 * 16 = 240 < 256
    double result = 0;

    std::vector<double> onevec(n_size, 1);
    std::vector<double> minusonevec(n_size, -1);

    size_t samples = targetvec.size()/n_size;

    for(size_t s = 0; s < samples; s += n_size){

        std::vector<std::vector<double>> inputmatrix(6);

        for (size_t i = 0; i < n_size; ++i) {
            for (size_t j = 0; j < n_size; ++j) {
                inputmatrix[0].push_back(targetvec[s + i]);
            }
        }
        inputmatrix[0].insert(inputmatrix[0].end(), onevec.begin(), onevec.end());

        for (size_t i = 0; i < n_size; ++i) {
            for (size_t j = 0; j < n_size; ++j) {
                inputmatrix[1].push_back(targetvec[s + j]);
            }
        }
        inputmatrix[1].insert(inputmatrix[1].end(), onevec.begin(), onevec.end());

        for (size_t i = 0; i < n_size; ++i) {
            for (size_t j = 0; j < n_size; ++j) {
                inputmatrix[2].push_back(kernel(pointsvec[s + i], pointsvec[s + j]));
            }
        }
        inputmatrix[2].insert(inputmatrix[2].end(), onevec.begin(), onevec.end());

        for (size_t i = 0; i < n_size; ++i) {
            for (size_t j = 0; j < n_size; ++j) {
                inputmatrix[3].push_back(targetvec[s + i]);
            }
        }
        inputmatrix[3].insert(inputmatrix[3].end(), onevec.begin(), onevec.end());

        for (size_t i = 0; i < n_size; ++i) {
            for (size_t j = 0; j < n_size; ++j) {
                inputmatrix[4].push_back(targetvec[s + j]);
            }
        }
        inputmatrix[4].insert(inputmatrix[4].end(), minusonevec.begin(), minusonevec.end());

        for (size_t i = 0; i < n_size; ++i) {
            for (size_t j = 0; j < n_size; ++j) {
                inputmatrix[5].push_back(0.5);
            }
        }
        inputmatrix[5].insert(inputmatrix[5].end(), alphavec.begin() + s, alphavec.begin() + s + n_size - 1);

        result += slap(argc, argv, inputmatrix);
    }

    return result;
}

// TakeStep method
bool takeStep(int argc, char **argv, int i1, int i2) {
    if (i1 == i2) return false;

    double alpha1 = alpha[i1], alpha2 = alpha[i2];
    int y1 = target[i1], y2 = target[i2];
    double E1 = SVMOutputonpoint(argc, argv, i1) - y1;
    double E2 = SVMOutputonpoint(argc, argv, i2) - y2;
    double s = y1 * y2;

    double L, H;
    if (y1 != y2) {
        L = max(0.0, alpha2 - alpha1);
        H = min(C, C + alpha2 - alpha1);
    } else {
        L = max(0.0, alpha2 + alpha1 - C);
        H = min(C, alpha2 + alpha1);
    }
    if (L == H) return false;

    double k11 = kernel(points[i1], points[i1]);
    double k12 = kernel(points[i1], points[i2]);
    double k22 = kernel(points[i2], points[i2]);
    double eta = k11 + k22 - 2 * k12;

    double a2;
    if (eta > 0) {
        a2 = alpha2 + y2 * (E1 - E2) / eta;
        if (a2 < L) a2 = L;
        else if (a2 > H) a2 = H;
    } else {
        std::vector<double> alphavec_L = alpha;
        alphavec_L[i2] = L;
        double Lobj = objectiveFunction(argc, argv, alphavec_L, target, points);

        std::vector<double> alphavec_H = alpha;
        alphavec_H[i2] = H;
        double Hobj = objectiveFunction(argc, argv, alphavec_H, target, points);

        if (Lobj < Hobj - eps) a2 = L;
        else if (Lobj > Hobj + eps) a2 = H;
        else {
            a2 = alpha2;
        }
    }

    if (abs(a2 - alpha2) < eps * (a2 + alpha2 + eps)) return false;

    double a1 = alpha1 + s * (alpha2 - a2);

    // Update threshold b
    double b1 = E1 + y1 * (a1 - alpha1) * k11 + y2 * (a2 - alpha2) * k12 + b;
    double b2 = E2 + y1 * (a1 - alpha1) * k12 + y2 * (a2 - alpha2) * k22 + b;
    if (0 < a1 && a1 < C) b = b1;
    else if (0 < a2 && a2 < C) b = b2;
    else b = (b1 + b2) / 2;

    // Update weights w

    for (size_t i = 0; i < w.size(); i++) {
        w[i] += y1 * (a1 - alpha1) * points[i1][i] + y2 * (a2 - alpha2) * points[i2][i];
    }

    alpha[i1] = a1;
    alpha[i2] = a2;

    return true;
}

int examineExample(int argc, char **argv, int i2){
    double y2 = target[i2];
    double alpha2 = alpha[i2];
    double E2 = SVMOutputonpoint(argc, argv, i2) - y2;
    double r2 = E2 * y2;

    if ((r2 < -tol && alpha2 < C) || (r2 > tol && alpha2 > 0)){
        for (size_t i1 = 0; i1 < alpha.size(); ++i1) {
            if (takeStep(argc, argv, i1, i2)) return 1;
        }
    }
    return 0;
}

// SMO method
void SMO(int argc, char **argv) {
    numChanged = 0;
    bool examineAll = true;

    while (numChanged > 0 || examineAll) {
        numChanged = 0;
        if (examineAll) {
            for (size_t i = 0; i < points[0].size(); i++)
                numChanged += examineExample(argc, argv, i);
        } else {
            for (size_t i = 0; i < points[0].size(); i++)
                if (alpha[i] != 0 && alpha[i] < C)
                    numChanged += examineExample(argc, argv, i);
        }

        if (examineAll) examineAll = false;
        else if (numChanged == 0) examineAll = true;
    }
}

void loadCSV(const string& filename, vector<vector<double>>& points, vector<int>& target) {
    ifstream file(filename);
    if (!file.is_open()) {
        cerr << "Error opening file: " << filename << endl;
        exit(1);
    }

    string line;

    // Skip the header row
    getline(file, line);

    while (getline(file, line)) {
        stringstream ss(line);
        string value;
        vector<double> point;
        int label;

        // Read features (semicolon-delimited)
        for (int i = 0; i < 11; i++) { // First 11 columns are features
            getline(ss, value, ';'); // Use semicolon as the delimiter
            point.push_back(stod(value)); // Convert to double
        }

        // Read label (quality)
        getline(ss, value, ';'); // Last column
        int quality = stoi(value); // Convert to integer

        // Transform quality into binary labels (+1 for good, -1 for not good)
        label = (quality >= 6) ? 1 : -1;

        points.push_back(point);
        target.push_back(label);
    }

    file.close();
}

int main(int argc, char **argv){
    // Load the dataset
    loadCSV("winequality-red.csv", points, target);

    // Initialize alpha and weight vectors
    alpha = vector<double>(points[0].size(), 0.0);
    w = vector<double>(points[0].size(), 0.0);

    // Run the SMO algorithm
    SMO(argc, argv);

    // Display results
    cout << "Final alpha values:" << endl;
    for (double a : alpha) cout << a << " ";
    cout << endl;

    cout << "Bias (b): " << b << endl;

    cout << "Weight vector (w): ";
    for (double wi : w) cout << wi << " ";
    cout << endl;

    return 0;
}