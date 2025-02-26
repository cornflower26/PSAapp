//
// Created by Antonia Januszewicz on 2/17/25.
//
#include "fhe_inference.cpp"
#ifndef GENERATOR

#define GENERATOR

// Coefficient structure
struct VectorElement {
    std::vector<std::pair<double, int>> terms;  // coefficient, unknown index
};

// Term with coefficient structure with exponent
struct Term {
    std::vector<std::pair<int, int>> variables; //index, exponent
    double coefficient;
};

// Expression with coefficient structure with exponent
struct Expression {
    std::vector<Term> terms;
};
using ExpressionMatrix = std::vector<std::vector<Expression>>;


// Helper function to get canonical form of variables (sorted)
static std::vector<std::pair<int, int>> getCanonicalVariables(std::vector<std::pair<int, int>> vars) {
    std::sort(vars.begin(), vars.end());
    return vars;
}

// Comparison function for terms
struct TermCompare {
    bool operator()(const Term& t1, const Term& t2) const {
        auto vars1 = getCanonicalVariables(t1.variables);
        auto vars2 = getCanonicalVariables(t2.variables);

        // First compare by total degree (sum of exponents)
        int degree1 = 0, degree2 = 0;
        for (const auto& v : vars1) degree1 += v.second;
        for (const auto& v : vars2) degree2 += v.second;

        if (degree1 != degree2) return degree1 > degree2;

        // Then compare by variables
        if (vars1 != vars2) return vars1 < vars2;

        // Finally compare by coefficient
        return std::abs(t1.coefficient) > std::abs(t2.coefficient);
    }
};

// Helper struct for term combination
struct TermKey {
    std::vector<std::pair<int, int>> vars;

    bool operator<(const TermKey& other) const {
        return vars < other.vars;
    }
};

// Helper function to add two expressions together with like term combination
static Expression addExpressions(const Expression& e1, const Expression& e2) {
    Expression result;

    // Use map to combine like terms efficiently
    std::map<TermKey, double> termMap;

    // Process all terms from both expressions
    for (const auto& term : e1.terms) {
        TermKey key{getCanonicalVariables(term.variables)};
        termMap[key] += term.coefficient;
    }

    for (const auto& term : e2.terms) {
        TermKey key{getCanonicalVariables(term.variables)};
        termMap[key] += term.coefficient;
    }

    // Create terms from map entries
    for (const auto& [key, coeff] : termMap) {
        if (std::abs(coeff) > 1e-10) {  // Skip terms with near-zero coefficients
            Term term;
            term.variables = key.vars;
            term.coefficient = coeff;
            result.terms.push_back(term);
        }
    }

    // Sort terms in canonical order
    std::sort(result.terms.begin(), result.terms.end(), TermCompare());

    return result;
}

// Function to add two vectors of expressions
static std::vector<Expression> addVectors(
        const std::vector<Expression>& vec1,
        const std::vector<Expression>& vec2) {

    if (vec1.size() != vec2.size()) {
        throw std::invalid_argument("Vector sizes must match for addition");
    }

    std::vector<Expression> result;
    result.reserve(vec1.size());

    // Add corresponding elements
    for (size_t i = 0; i < vec1.size(); ++i) {
        result.push_back(addExpressions(vec1[i], vec2[i]));
    }

    return result;
}
// Helper function to cube a single expression
static Expression cubeExpression(const Expression& expr) {
    Expression result;

    // First multiply expr * expr to get square
    Expression square;
    for (const Term& t1 : expr.terms) {
        for (const Term& t2 : expr.terms) {
            Term newTerm;
            newTerm.coefficient = t1.coefficient * t2.coefficient;

            // Combine variables and their exponents
            newTerm.variables = t1.variables;
            for (const auto& var : t2.variables) {
                bool found = false;
                for (auto& existing : newTerm.variables) {
                    if (existing.first == var.first) {
                        existing.second += var.second;
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    newTerm.variables.push_back(var);
                }
            }
            square.terms.push_back(newTerm);
        }
    }

    // Then multiply square * expr to get cube
    for (const Term& t1 : square.terms) {
        for (const Term& t2 : expr.terms) {
            Term newTerm;
            newTerm.coefficient = t1.coefficient * t2.coefficient;

            // Combine variables and their exponents
            newTerm.variables = t1.variables;
            for (const auto& var : t2.variables) {
                bool found = false;
                for (auto& existing : newTerm.variables) {
                    if (existing.first == var.first) {
                        existing.second += var.second;
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    newTerm.variables.push_back(var);
                }
            }
            result.terms.push_back(newTerm);
        }
    }

    return result;
}

// Function to cube a vector of expressions
static std::vector<Expression> cubeVector(const std::vector<Expression>& vec) {
    std::vector<Expression> result;
    result.reserve(vec.size());

    // Cube each expression independently
    for (const Expression& expr : vec) {
        result.push_back(cubeExpression(expr));
    }

    return result;
}

static Expression multiply_expression_by_scalar(const Expression& expr, double scalar) {
    Expression result = expr;
    for (auto& term : result.terms) {
        term.coefficient *= scalar;
    }
    return result;
}

// Function to multiply a vector of expressions by a scalar
static std::vector<Expression> multiplyVectorByScalar(
        const std::vector<Expression>& vec,
        double scalar) {

    std::vector<Expression> result;
    result.reserve(vec.size());

    // Multiply each expression by the scalar
    for (const Expression& expr : vec) {
        result.push_back(multiply_expression_by_scalar(expr, scalar));
    }

    return result;
}

// Function to multiply a vector of expressions by a matrix of scalars
static std::vector<Expression> multiplyVectorByScalarMatrix(
        const std::vector<Expression>& vec,
        const std::vector<std::vector<double>>& matrix) {

    if (matrix.empty() || matrix[0].empty()) {
        throw std::invalid_argument("Matrix cannot be empty");
    }

    if (vec.size() != matrix[0].size()) {
        throw std::invalid_argument("Matrix columns must match vector size");
    }

    std::vector<Expression> result(matrix.size());

    // For each row in the matrix
    for (size_t i = 0; i < matrix.size(); ++i) {
        Expression sum;

        // For each column in the matrix
        for (size_t j = 0; j < matrix[i].size(); ++j) {
            // Multiply vector element by matrix element and add to sum
            Expression scaledExpr = multiply_expression_by_scalar(vec[j], matrix[i][j]);

            // Add terms to sum
            Expression tempSum = addExpressions(sum, scaledExpr);
            sum = tempSum;
        }

        result[i] = sum;
    }

    return result;
}

// Matrix by vector multiplication
static Expression multiply_matrix_row_by_vector(const std::vector<double>& row, size_t vec_size) {
    Expression result;

    for (size_t i = 0; i < row.size(); i++) {
        if (row[i] != 0) {
            Term term;
            term.coefficient = row[i];
            term.variables.push_back(std::pair<int, int>(i,1));  // x_i with exponent 1
            result.terms.push_back(term);
        }
    }

    return result;
}


// Print the expressions
static void print_term(const Term& term, std::ofstream& file) {
    if (term.coefficient == 0) return;

    if (term.coefficient > 0 && term.coefficient != 1)
        file << term.coefficient;
    else if (term.coefficient == -1)
        file << "-";
    else if (term.coefficient < 0)
        file << term.coefficient;
    else if (term.coefficient == 1 && term.variables.empty())
        file << "1";

    for (const auto& var : term.variables) {
        file << "x" << (var.first + 1);
        if (var.second > 1)
            file << "^" << var.second;
    }
}

static void print_expression(const Expression& expr, std::ofstream &file) {
    bool first = true;
    for (const auto& term : expr.terms) {
        if (!first && term.coefficient > 0) file << " + ";
        else if (!first) file << " ";
        first = false;
        print_term(term, file);
    }
    file << "\n";
}

static void print_matrix(const ExpressionMatrix& matrix, std::ofstream& file) {
    for (const auto& row : matrix) {
        for (const auto& expr : row) {
            print_expression(expr, file);
            file << "\t";
        }
        file << "\n";
    }
}
// Function to extract coefficients from a vector of expressions
static std::vector<std::vector<double>> extractCoefficients(const std::vector<Expression>& expressions) {
    std::vector<std::vector<double>> coefficients;
    coefficients.reserve(expressions.size());

    // For each expression
    for (const Expression& expr : expressions) {
        std::vector<double> exprCoeffs;
        exprCoeffs.reserve(expr.terms.size());

        // For each term in the expression
        for (const Term& term : expr.terms) {
            exprCoeffs.push_back(term.coefficient);
        }

        coefficients.push_back(exprCoeffs);
    }

    return coefficients;
}

// Function to extract exponents of a specific variable from a vector of expressions
static std::vector<std::vector<int>> extractVariableExponents(
        const std::vector<Expression>& expressions,
        int variableIndex) {

    std::vector<std::vector<int>> exponents;
    exponents.reserve(expressions.size());

    // For each expression
    for (const Expression& expr : expressions) {
        std::vector<int> exprExponents;
        exprExponents.reserve(expr.terms.size());

        // For each term in the expression
        for (const Term& term : expr.terms) {
            // Look for the variable in this term
            bool found = false;
            for (const auto& var : term.variables) {
                if (var.first == variableIndex) {
                    exprExponents.push_back(var.second);
                    found = true;
                    break;
                }
            }
            // If variable wasn't found in this term, its exponent is 0
            if (!found) {
                exprExponents.push_back(0);
            }
        }

        exponents.push_back(exprExponents);
    }

    return exponents;
}

// Helper function to find the maximum variable index in an expression
static int findMaxVariableIndex(const Expression& expr) {
    int maxIndex = -1;
    for (const Term& term : expr.terms) {
        for (const auto& var : term.variables) {
            maxIndex = std::max(maxIndex, var.first);
        }
    }
    return maxIndex;
}

// Function to append two expression vectors with incremented variable indices for second vector
static std::vector<Expression> appendExpressionVectorsWithNewVariables(
        const std::vector<Expression>& vec1,
        const std::vector<Expression>& vec2) {

    if (vec1.size() != vec2.size()) {
        throw std::invalid_argument("Vector sizes must match for appending");
    }

    std::vector<Expression> result;
    result.reserve(vec1.size());

    // Find maximum variable index across all expressions in vec1
    int maxIndex = -1;
    for (const Expression& expr : vec1) {
        maxIndex = std::max(maxIndex, findMaxVariableIndex(expr));
    }
    maxIndex++; // Start new indices from here

    // For each pair of expressions
    for (size_t i = 0; i < vec1.size(); ++i) {
        Expression combinedExpr;

        // Add all terms from first expression as is
        combinedExpr.terms = vec1[i].terms;

        // Add terms from second expression with incremented variable indices
        for (const Term& term : vec2[i].terms) {
            Term newTerm;
            newTerm.coefficient = term.coefficient;

            // Increment variable indices
            for (const auto& var : term.variables) {
                newTerm.variables.push_back({var.first + maxIndex, var.second});
            }

            combinedExpr.terms.push_back(newTerm);
        }

        result.push_back(combinedExpr);
    }

    return result;
}


static std::vector<Expression> multiply_matrix_by_vector(
        const std::vector<std::vector<double>>& matrix,
        size_t vector_size) {

    if (matrix[0].size() != vector_size) {
        throw std::runtime_error("Matrix columns must match vector size");
    }

    std::vector<Expression> result;
    for (const auto& row : matrix) {
        result.push_back(multiply_matrix_row_by_vector(row, vector_size));
    }

    return result;
}


static int generate() {
    const int EMBEDDING_SIZE = 128;
    const int STEP_NUM = 128;
    int sample_num = 256;
    usint numSlots = (1<<15);
    int b_id = 0;

    // Retrieve weight from .bin files
    std::string embedding_file_name = std::string("../train/test_input/embedding_batch_") + std::to_string(b_id) + std::string(".bin");
    std::string ground_truth_file_name = std::string("../train/test_input/ground_truth_batch_") + std::to_string(b_id) + std::string(".bin");
    float *rnn_ih_t = new float[EMBEDDING_SIZE * STEP_NUM];
    float *rnn_hh_t = new float[STEP_NUM * STEP_NUM];
    float *fc_weight_t = new float[2 * STEP_NUM];
    float *fc_bias_t = new float[2];
    float *embedding_in = new float[sample_num * STEP_NUM * EMBEDDING_SIZE];
    float *ground_truth = new float[sample_num];
    FILE *file;
    file = fopen("../train/trained_rnn_ih.bin", "rb");
    fread(rnn_ih_t, sizeof(float), EMBEDDING_SIZE * STEP_NUM, file);
    fclose(file);
    file = fopen("../train/trained_rnn_hh.bin", "rb");
    fread(rnn_hh_t, sizeof(float), STEP_NUM * STEP_NUM, file);
    fclose(file);
    file = fopen("../train/trained_fc_weight.bin", "rb");
    fread(fc_weight_t, sizeof(float), 2 * STEP_NUM, file);
    fclose(file);
    file = fopen("../train/trained_fc_bias.bin", "rb");
    fread(fc_bias_t, sizeof(float), 2, file);
    fclose(file);
    file = fopen(embedding_file_name.c_str(), "rb");
    fread(embedding_in, sizeof(float), sample_num * STEP_NUM * EMBEDDING_SIZE, file);
    fclose(file);
    file = fopen(ground_truth_file_name.c_str(), "rb");
    fread(ground_truth, sizeof(float), sample_num, file);
    fclose(file);
    usint batch_size = numSlots / EMBEDDING_SIZE;
    // Pack the plaintext matrix in diagnal order

    std::vector<double> batched_embedding(batch_size * EMBEDDING_SIZE);
    std::vector<double> batched_hidden_ref(batch_size * STEP_NUM);

    int batch_id = 0;
    std::cout << std::endl;

    std::vector<std::vector<double>> ih_matrix(128, std::vector<double>(128));
    for (int i = 0; i < 128; i++) {
        std::vector<double> row(std::vector<double>(128));
        for (int j = 0; j < 128; j++) {
            row[j] = rnn_ih_t[i * 128 + j];
        }
        ih_matrix[i] = row;
    }
    std::vector<std::vector<double>> hh_matrix(128, std::vector<double>(128));
    for (int i = 0; i < 128; i++) {
        std::vector<double> row(std::vector<double>(128));
        for (int j = 0; j < 128; j++) {
            row[j] = rnn_ih_t[i * 128 + j];
        }
        hh_matrix[i] = row;
    }
    std::vector<std::vector<double>> fc_matrix(2, std::vector<double>(128));
    for (int i = 0; i < 2; i++) {
        std::vector<double> row(std::vector<double>(128));
        for (int j = 0; j < 128; j++) {
            row[j] = fc_weight_t[i * 128 + j];
        }
        fc_matrix[i] = row;
    }
    std::cout << "Matrix formation " << std::endl;
    auto rnn_ih = multiply_matrix_by_vector(ih_matrix, 128);
    auto rnn_hh = multiply_matrix_by_vector(hh_matrix, 128);
    std::cout << "Finished matrix multiplication 1" << std::endl;

    auto sumInputVectors = appendExpressionVectorsWithNewVariables(rnn_ih, rnn_hh);

    //auto cube = cubeVector(sumInputVectors);
    //std::cout << "Finished cubing " << std::endl;

    //auto mid = multiplyVectorByScalar(cube, -0.00163574303018748);
    //std::cout << "Finished first scalar multiplication " << std::endl;
    //auto mid2 = multiplyVectorByScalar(sumInputVectors, 0.249476365628036);
    //std::cout << "Finished second scalar multiplication " << std::endl;

    //auto rnn_2 = addVectors(mid, mid2);
    //std::cout << "Finished vector addition and Hidden Layer" << std::endl;



    auto rnn_3 = multiply_matrix_by_vector(fc_matrix,128);
    std::cout << "Finished matrix multiplication Fully Connected Layer" << std::endl;


    std::ofstream outFile("BigOutput4.txt");


    std::cout << "Result vector:\n";
    for (const auto &element: sumInputVectors) {
        if (outFile.is_open()) print_expression(element, outFile);
        //outFile << "term";
        outFile << " \n";
    }

// Close the file
    outFile.close();


    std::ofstream outFile1("CoeffHiddenOutput.txt");
    std::cout << "Coefficients for hidden layer \n";

    std::vector<std::vector<double>> hidden_coeff = extractCoefficients(sumInputVectors);
//outFile1 << extractCoefficients(rnn_3);
    for (std::vector<double> elements: hidden_coeff) {
        for (double element: elements) {
            outFile1 << element << ",";
        }
        outFile1 << "\n";
    }

// Close the file
    outFile1.close();

    std::ofstream outFile2("CoeffFCOutput.txt");
    std::cout << "Coefficients for FC Layer \n";

    std::vector<std::vector<double>> fc_coeff = extractCoefficients(rnn_3);
//outFile1 << extractCoefficients(rnn_3);
    for (std::vector<double> elements: fc_coeff) {
        for (double element: elements) {
            outFile2 << element << ",";
        }
        outFile2 << "\n";
    }

// Close the file
    outFile2.close();


    std::cout << "Hidden variables\n";
    for (int i = 0; i < 256; i++) {
        std::string name = "x";
        name.append(std::to_string(i));
        name.append("variablehl.txt");
        std::ofstream outFilen(name);
        std::vector<std::vector<int>> b = extractVariableExponents(sumInputVectors, i + 1);
            for (std::vector<int> elements: b) {
                for (int element: elements) {
                    outFilen << element << ",";
                }
                outFilen << "\n";
            }
        // Close the file
        outFilen.close();
    }

    std::cout << "FC variables\n";
    for (int i = 0; i < 128; i++) {
        std::string name = "x";
        name.append(std::to_string(i));
        name.append("variablefc.txt");
        std::ofstream outFilen(name);
        std::vector<std::vector<int>> b = extractVariableExponents(rnn_3, i + 1);
        for (std::vector<int> elements: b) {
            for (int element: elements) {
                outFilen << element << ",";
            }
            outFilen << "\n";
        }
        // Close the file
        outFilen.close();
    }


// Restore cout to its original state
    std::cout << hidden_coeff.size() << " number of outputs for hidden" << std::endl;
    std::cout << hidden_coeff[0].size() << " number of terms for hidden" << std::endl;

    std::cout << fc_coeff.size() << " number of output for FC" << std::endl;
    std::cout << fc_coeff[0].size() << " number of terms for FC " << std::endl;

    return 1;
}

#endif GENERATOR