#include <iostream>
#include <vector>
#include <cmath>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <chrono>

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

// SVM output for a given point
double SVMOutputonpoint(int k){
    double u = kernel(w, points[k]) - b;
    return u;
}

// Classification
int classification(const vector<double>& new_point) {
    double decision_value = kernel(w, new_point) - b;

    if (decision_value > 0) {
        return 1;
    } else {
        return -1;
    }
}

// Objective function
double objectiveFunction(std::vector<double>& alphavec, std::vector<int>& targetvec, std::vector<std::vector<double>>& pointsvec) {

    double sum = 0;
    double sum_alpha = 0;

    for (size_t i = 0; i < targetvec.size(); i++){
        for (size_t j = 0; j < targetvec.size(); j++){
            sum += targetvec[i] * targetvec[j] * kernel(points[i], points[j]) * alphavec[i] * alphavec[j];
        }
    }

    for (size_t i = 0; i < targetvec.size(); i++){
        sum_alpha += alphavec[i];
    }

    double result = 0.5 * sum - sum_alpha;

    return result;
}

// TakeStep method
bool takeStep(int i1, int i2) {
    if (i1 == i2) return false;

    double alpha1 = alpha[i1], alpha2 = alpha[i2];
    int y1 = target[i1], y2 = target[i2];
    double E1 = SVMOutputonpoint(i1) - y1;
    double E2 = SVMOutputonpoint(i2) - y2;
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
        double Lobj = objectiveFunction(alphavec_L, target, points);

        std::vector<double> alphavec_H = alpha;
        alphavec_H[i2] = H;
        double Hobj = objectiveFunction(alphavec_H, target, points);

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

int examineExample(int i2){
    double y2 = target[i2];
    double alpha2 = alpha[i2];
    double E2 = SVMOutputonpoint(i2) - y2;
    double r2 = E2 * y2;

    if ((r2 < -tol && alpha2 < C) || (r2 > tol && alpha2 > 0)){
        for (size_t i1 = 0; i1 < alpha.size(); ++i1) {
            if (takeStep(i1, i2)) return 1;
        }
    }
    return 0;
}

// SMO method
void SMO() {
    numChanged = 0;
    bool examineAll = true;

    while (numChanged > 0 || examineAll) {
        numChanged = 0;
        if (examineAll) {
            for (size_t i = 0; i < points[0].size(); i++)
                numChanged += examineExample(i);
        } else {
            for (size_t i = 0; i < points[0].size(); i++)
                if (alpha[i] != 0 && alpha[i] < C)
                    numChanged += examineExample(i);
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

int main(){
    auto start = std::chrono::high_resolution_clock::now();
    // Load the dataset
    loadCSV("../winequality-white-acc1.csv", points, target);

    // Initialize alpha and weight vectors
    alpha = vector<double>(points[0].size(), 0.0);
    w = vector<double>(points[0].size(), 0.0);

    // Run the SMO algorithm
    SMO();

    // Display results
    cout << "Final alpha values:" << endl;
    for (double a : alpha) cout << a << " ";
    cout << endl;

    cout << "Bias (b): " << b << endl;

    cout << "Weight vector (w): ";
    for (double wi : w) cout << wi << " ";
    cout << endl;

    auto end = std::chrono::high_resolution_clock::now();

    vector<vector<double>> points_acc;
    vector<int> target_acc;
    loadCSV("../winequality-white-acc2.csv", points_acc, target_acc);

    vector<double> smo_values;
    for (size_t i = 0; i < target_acc.size(); ++i) {
        smo_values.push_back(classification(points_acc[i]) - target_acc[i]);
    }

    double zeros = std::count(smo_values.begin(), smo_values.end(), 0);
    double accuracy_percentage = (zeros / smo_values.size()) * 100;

    std::cout << "Training samples: " << target.size() << std::endl;
    std::cout << "Testing samples: " << target_acc.size() << std::endl;
    cout << "Accuracy: " << accuracy_percentage << "%" << endl;

    std::chrono::duration<double, std::milli> duration = end - start;
    std::cout << "Run time: " << duration.count() << " ms" << std::endl;

    return 0;
}