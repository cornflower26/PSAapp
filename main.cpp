//#include <core/lattice/lat-hal.h>
//#include <pke/openfhe.h>
#include <iostream>
#include <getopt.h>
#include <execinfo.h>
#include <signal.h>
#include <unistd.h>
#include "PSA-cryptocontext.h"

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

    int main(int argc, char ** argv) {
        signal(SIGSEGV, handler);
        //std::cout << "Hello, World!" << std::endl;
        //DCRTPoly a = DCRTPoly();
        unsigned int plain_bits = 8; //log t
        unsigned int num_users = 2; //n
        unsigned int iters = 2; //i
        unsigned int k_prime = 1; //k
        Scheme scheme1 = MS;

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

        pp.TestPolynomialEncryption(true, iters, poly_noise_times, poly_enc_times);
        // pp.TestPolynomialEncryption(1, MAX_CTEXTS_DEFAULT, poly_noise_times, poly_enc_times);

        std::vector<double> decrypt_times;


        pp.TestPolynomialDecryption(iters, decrypt_times);


        for(const double d : poly_noise_times){
            std::cout << "poly_noise_times " << d << '\n';
        }
        for(const double d : poly_enc_times){
            std::cout << "poly_enc_times " << d << '\n';
        }
        for(const double d : decrypt_times){
            std::cout << "decrypt_times " << d << '\n';
        }

        return 0;
    }

