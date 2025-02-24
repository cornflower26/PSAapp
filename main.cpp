//#include <core/lattice/lat-hal.h>
//#include <pke/openfhe.h>
#include <iostream>
#include <getopt.h>
#include <execinfo.h>
#include <signal.h>
#include <unistd.h>
#include <math/dftransform.h>
#include "PSA-cryptocontext.h"
#include "chunk_reader.cpp"
#include "psa_inference_polynomial_generator.cpp"
using namespace lbcrypto;

constexpr size_t EMBEDDING_SIZE = 128;

std::vector<std::vector<float>> readVectorsFromCSV(const std::string& filename) {
    std::vector<std::vector<float>> vectors;
    std::ifstream file(filename);

    if (!file.is_open()) {
        throw std::runtime_error("Unable to open file: " + filename);
    }

    std::vector<float> currentVector;
    std::string currentNumber;
    char c;
    bool hasData = false;

    while (file.get(c)) {
        hasData = true;

        if (c == ',') {
            // Process number at comma
            if (!currentNumber.empty()) {
                try {
                    currentVector.push_back(std::stof(currentNumber));
                } catch (const std::invalid_argument& e) {
                    std::cerr << "Warning: Invalid float value found: " << currentNumber << std::endl;
                }
                currentNumber.clear();
            }
        }
        else if (c == '\n' || c == '\r') {
            // Process number at line end
            if (!currentNumber.empty()) {
                try {
                    currentVector.push_back(std::stof(currentNumber));
                } catch (const std::invalid_argument& e) {
                    std::cerr << "Warning: Invalid float value found: " << currentNumber << std::endl;
                }
                currentNumber.clear();
            }

            // Add vector if it's not empty and reset
            if (!currentVector.empty()) {
                vectors.push_back(currentVector);
                currentVector.clear();
            }

            // Handle \r\n line endings
            if (c == '\r') {
                file.get(c);
                if (c != '\n') {
                    file.putback(c);
                }
            }
        }
        else if (std::isspace(c)) {
            // Skip other whitespace
            continue;
        }
        else {
            // Build number string
            currentNumber += c;
        }
    }

    // Handle last number if file doesn't end with newline
    if (!currentNumber.empty()) {
        try {
            currentVector.push_back(std::stof(currentNumber));
        } catch (const std::invalid_argument& e) {
            std::cerr << "Warning: Invalid float value found: " << currentNumber << std::endl;
        }
    }

    // Handle last vector if file doesn't end with newline
    if (!currentVector.empty()) {
        vectors.push_back(currentVector);
    }

    // Check if file was empty
    if (!hasData) {
        std::cerr << "Warning: Empty file" << std::endl;
    }

    file.close();
    return vectors;
}


// Function to read embeddings from a binary file
// Returns vector of vectors containing the embeddings
// Throws runtime_error if file operations fail
std::vector<std::vector<float>> read_embeddings(const std::string& filename, size_t num_rows) {
    std::ifstream input(filename, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Could not open input file: " + filename);
    }

    // Vector to store embeddings
    std::vector<std::vector<float>> embeddings;
    embeddings.reserve(num_rows);

    // Temporary buffer for reading one row
    std::vector<float> row(EMBEDDING_SIZE);

    // Read requested number of rows
    for (size_t i = 0; i < num_rows; ++i) {
        if (!input.read(reinterpret_cast<char*>(row.data()),
                        EMBEDDING_SIZE * sizeof(float))) {
            if (input.eof()) {
                throw std::runtime_error("File contains fewer than " +
                                         std::to_string(num_rows) + " rows");
            } else {
                throw std::runtime_error("Failed to read row " +
                                         std::to_string(i + 1));
            }
        }
        embeddings.push_back(row);
    }

    return embeddings;
}


// Optional: Helper function to print embeddings
void print_embeddings(const std::vector<std::vector<float>>& embeddings) {
    std::cout << std::fixed << std::setprecision(6);
    for (const auto& row : embeddings) {
        for (size_t i = 0; i < EMBEDDING_SIZE; ++i) {
            if (i > 0) std::cout << " ";
            std::cout << row[i];
        }
        std::cout << "\n";
    }
}



int main() {
    std::cout << "Hello Word 95" << std::endl;
    //for (int i = 0;i < 1; ++i) {
    //    fhe_rnn(0);
    //}
    generate();



    try{
        auto embeddings = read_embeddings("../train/test_input/embedding_batch_0.bin", 1);
        print_embeddings(embeddings);

        // Example of how to access values programmatically
        if (!embeddings.empty() && !embeddings[0].empty()) {
            float first_value = embeddings[0][0];
            std::cout << "First value: " << first_value << "\n";
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    const int EMBEDDING_SIZE = 128;
    const int STEP_NUM = 128;
    int sample_num = 256;
    usint numSlots = (1<<15);
    int b_id = 0;

    unsigned int plain_bits = 32; //log t
    unsigned int num_users = 128; //n
    unsigned int iters = 1; //i
    unsigned int k_prime = 1; //k
    Scheme scheme1 = NS;

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

    //std::vector<std::vector<float>> a = readVectorsFromCSV("../files/CoeffOutput.txt");
    //std::cout << "Coefficient size " << a.size()<< std::endl;
    //std::cout << "Coefficients per thing " << a[0].size() << " " << a[1].size() << std::endl;

    // Run reference RNN computation
    for (int i = 0;i < STEP_NUM; ++i) {
        for (int j = 0;j < batch_size; ++j) {
            for (int k = 0;k < EMBEDDING_SIZE; ++k) {
                batched_embedding[k * batch_size + j] = embedding_in[((j + batch_id * batch_size) * EMBEDDING_SIZE + i) * EMBEDDING_SIZE + k];
            }
        }
        std::vector<double> result_ref(batch_size * STEP_NUM);
        for (int j = 0; j < 128; ++j) {
            for (int k = 0; k < batch_size; ++k) {
                for (int l = 0; l < 128; ++l) {
                    result_ref[j * batch_size + k] += batched_embedding[l * batch_size + k] * rnn_ih_t[j * 128 + l];
                    result_ref[j * batch_size + k] += batched_hidden_ref[l * batch_size + k] * rnn_hh_t[j * 128 + l];
                }
                // Tanh activation
                result_ref[j * batch_size + k] = activation(result_ref[j * batch_size + k]);

            }
        }
        batched_hidden_ref = result_ref;
    }

    std::vector<double> embedding(EMBEDDING_SIZE*STEP_NUM);
        for (int i = 0; i < STEP_NUM; i++) {
            for (int j = 0; j < EMBEDDING_SIZE; j++) {
                embedding[i * EMBEDDING_SIZE + j] = embedding_in[i * EMBEDDING_SIZE + j];
            }
        }

    int numInferences = STEP_NUM;
    std::pair<double, double> inference;
    ChunkReader reader("CoeffHiddenOutput.txt", 512);
    std::vector<ChunkReader> variables;
    variables.reserve(256);

    for (int a = 0; a < 256; a++) {
        std::string name = "x" + std::to_string(a);
        name += "variablehl.txt";
        variables.push_back(ChunkReader(name, 512));
    }


    std::vector<double> layer_output(128,0);
    std::vector<double> layer_input(128,0);
    for (int k = 0; k < STEP_NUM; k++) {
        std::cout << "step " << std::to_string(k) << "/" << STEP_NUM << std::endl;
        int which = 0;
        while (reader.hasNext()) {
            PSACryptocontext pp = PSACryptocontext(plain_bits, num_users, iters, scheme1);
            std::vector<double> poly_noise_times, poly_enc_times;
            pp.PolynomialEnvSetup(poly_noise_times, poly_enc_times);

            for (unsigned int i = 0; i < 256; i++) {
                std::vector<double> expvec(pp.aggregator.plaintextParams.GetRingDimension() / 2, 0);
                bool flag = 0;
                variables[i].nextChunk(expvec, flag);
                double val = 0;
                if (i < 128) val = embedding[k * EMBEDDING_SIZE + i];
                else val = layer_input[i%128];

                std::vector<double> inputvec(pp.aggregator.plaintextParams.GetRingDimension() / 2,
                                                 val);
                pp.PolynomialEncryption(
                            inputvec, expvec, i, poly_noise_times, poly_enc_times);

            }

            std::vector<double> decrypt_times, agg_times;
            std::vector<double> constants(pp.aggregator.plaintextParams.GetRingDimension() / 2, 0);
            bool flag = 0;
            reader.nextChunk(constants, flag);
            if (flag) which++;

            std::vector<double> outputvec = pp.PolynomialDecryption(constants, iters, decrypt_times);
            for (int b = 0; b < outputvec.size(); b++) layer_output[which] += outputvec[b];
        }
        std::cout << "Layer output: " << layer_output << std::endl;
        layer_input = layer_output;
        for (int a = 0; a < layer_output.size();a++) layer_output[a] = 0;
    }
    std::cout << "Final Layer Result for RNN " << layer_input << std::endl;

    ChunkReader reader2("CoeffFCOutput.txt", 512);
    std::vector<ChunkReader> variables2;
    variables2.reserve(128);

    for (int a = 0; a < 128; a++) {
        std::string name = "x" + std::to_string(a);
        name += "variablefc.txt";
        variables2.push_back(ChunkReader(name, 512));
    }

    bool which = 0;
    double total1, total2 = 0;
    while (reader2.hasNext()) {
        PSACryptocontext pp = PSACryptocontext(plain_bits, num_users, iters, scheme1);
        std::vector<double> poly_noise_times, poly_enc_times;
        pp.PolynomialEnvSetup(poly_noise_times, poly_enc_times);

        for (unsigned int i = 0; i < 128; i++) {
            std::vector<double> expvec(pp.aggregator.plaintextParams.GetRingDimension() / 2, 0);
            bool flag = 0;
            variables2[i].nextChunk(expvec, flag);
            std::vector<double> inputvec(pp.aggregator.plaintextParams.GetRingDimension() / 2,
                                         layer_input[i]);
            pp.PolynomialEncryption(
                    inputvec, expvec, i, poly_noise_times, poly_enc_times);

        }

        std::vector<double> decrypt_times, agg_times;
        std::vector<double> constants(pp.aggregator.plaintextParams.GetRingDimension() / 2, 0);
        bool flag = 0;
        reader.nextChunk(constants, flag);
        if (flag) which =1;

        std::vector<double> outputvec = pp.PolynomialDecryption(constants, iters, decrypt_times);
        if (which) for (int b = 0; b < outputvec.size(); b++) total1 += outputvec[b];
        else for (int b = 0; b < outputvec.size(); b++) total2 += outputvec[b];
    }
    
    total1 += fc_bias_t[0];
    total2 += fc_bias_t[1];
    //std::cout << std::endl;
    std::cout << "Output1 " << total1 << " and sigmoid " << sigmoid(total1);
    std::cout << " Output2 " << total2 << " and sigmoid " << sigmoid(total2) << std::endl;
    inference = std::pair<double, double>(sigmoid(total1),sigmoid(total2));


    // Run reference RNN computation
    std::vector<double> result_ref(batch_size * 2);
    for (int j = 0;j < 2; ++j) {
        for (int k = 0;k < batch_size; ++k) {
            for (int l = 0;l < 128; ++l) {
                result_ref[j * batch_size + k] += batched_hidden_ref[l * batch_size + k] * fc_weight_t[j * 128 + l];
            }
            result_ref[j * batch_size + k] += fc_bias_t[j];

            // Sigmoid activation
            result_ref[j * batch_size + k] = sigmoid(result_ref[j * batch_size + k]);
            //result_fhe[j * batch_size + k] = sigmoid(fhe_result_pt->GetRealPackedValue()[j * batch_size + k]);
        }
    }
    std::cout << std::endl;

    for (int k = 0;k < 1; ++k) {
        std::cout << "gt: " << ground_truth[batch_id * batch_size + k] << " ref out: [" << result_ref[k] << " ," << result_ref[k + batch_size] << "]"
                  << "ppsa out: [" << inference.first << " ," << inference.second << "]" << std::endl;

        ++num_inf;
        if (ground_truth[batch_id * batch_size + k] == 0) {
            if (result_ref[k] > 0.5) ++ num_ref_correct;
            if (inference.first > 0.5) ++ num_fhe_correct;
        } else {
            if (result_ref[k + batch_size] > 0.5) ++ num_ref_correct;
            if (inference.second > 0.5) ++ num_fhe_correct;
        }
    }
    std::cout << "ref accuracy:\t" << num_ref_correct << "/\t" << num_inf << "\t" << 100.0 * num_ref_correct / num_inf << "%" << std::endl
              << "fhe accuracy:\t" << num_fhe_correct << "/\t" << num_inf << "\t" << 100.0 * num_fhe_correct / num_inf << "%" << std::endl;


    std::cout << "Hello world" << std::endl;

    return 1;
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

int othermain(int argc, char ** argv) {
    signal(SIGSEGV, handler);
    std::cout << "Hello, World! " << std::endl;
    //DCRTPoly a = DCRTPoly();
    unsigned int plain_bits = 16; //log t
    unsigned int num_users = 50; //n
    unsigned int iters = 10; //i
    unsigned int k_prime = 1; //k
    Scheme scheme1 = NS;

    unsigned int N; //N

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
    MAX_CTEXTS_DEFAULT = N;
    MAX_CTEXTS_DEFAULT = k_prime;
    k_prime = MAX_CTEXTS_DEFAULT;

    //temp();

    //Code for testing SLAP, which isn't what this paper is about

    /**
    PSACryptocontext p = PSACryptocontext(plain_bits, num_users, iters, scheme1);
    std::vector<double> noise_times;
    std::vector<double> enc_times;
    std::vector<double> dec_times;
    p.TestEncryption(iters, false, noise_times, enc_times);

    p.TestDecryption(iters,dec_times);

    for(const double d : noise_times){
        std::cout << "noise_times " << d << '\n';
    }
    for(const double d : enc_times){
        std::cout << "enc_times " << d << '\n';
    }
    for(const double d : dec_times){
        std::cout << "dec_times " << d << '\n';
    }
     **/


    PSACryptocontext pp = PSACryptocontext(plain_bits, num_users, iters, scheme1);

    std::vector<double> poly_noise_times;
    std::vector<double> poly_enc_times;

    //pp.TestPolynomialEncryption(true, iters, poly_noise_times, poly_enc_times);
    // pp.TestPolynomialEncryption(1, MAX_CTEXTS_DEFAULT, poly_noise_times, poly_enc_times);

    pp.PolynomialEnvSetup(poly_noise_times, poly_enc_times);

    for (unsigned int i = 0; i < num_users; i++) {
        std::vector<double> inputvec(pp.aggregator.plaintextParams.GetRingDimension() / 2, 3);
        inputvec[2] = 5;
        std::vector<double> expvec(pp.aggregator.plaintextParams.GetRingDimension() / 2, 2);

        //std::cout << i << " input: " << inputvec << std::endl;

        pp.PolynomialEncryption(inputvec, expvec, i, poly_noise_times, poly_enc_times);
    }


    std::vector<double> decrypt_times;
    std::vector<double> agg_times;

    std::vector<double> constants(pp.aggregator.plaintextParams.GetRingDimension()/2,2);
    std::vector<double> outputvec = pp.PolynomialDecryption(constants, iters, decrypt_times);

    std::cout << "Final output: " << outputvec << std::endl;


    std::cout << "poly_noise_times " << '\n';
    int i = 0;
    for(const double d : poly_noise_times){
        if (i % 100 == 0) std::cout << d << '\n';
        i++;
    }
    i = 0;
    std::cout << "poly_enc_times " << '\n';
    for(const double d : poly_enc_times){
        if (i % 100 == 0) std::cout << d << '\n';
        i++;
    }
    //for (const double d: agg_times){
    //    std::cout << "poly_agg_times " << d << '\n';
    //}
    std::cout << "decrypt_times " << '\n';
    for(const double d : decrypt_times){
        std::cout << d << '\n';
    }


    return 0;
}
