//#include <core/lattice/lat-hal.h>
//#include <pke/openfhe.h>
#include <iostream>
#include <getopt.h>
#include "PSA-cryptocontext.h"



    int main(int argc, char ** argv) {
        //std::cout << "Hello, World!" << std::endl;
        //DCRTPoly a = DCRTPoly();
        unsigned int plain_bits = 5; //log t
        unsigned int packing_size = 16; //p
        unsigned int num_users = 10; //n
        unsigned int iters = 1; //i
        unsigned int k_prime = 1; //k
        unsigned int N = 1; //N

        int c;
          while((c = getopt(argc, argv, "t:p:n:i:k:N:")) != -1){
            switch(c){
            case 't':{
                plain_bits = atoi(optarg);
                break;
            }
            case 'p':{
                packing_size = atoi(optarg);
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
        /*
        PSACryptocontext p = PSACryptocontext(plain_bits, packing_size, num_users, iters, MS);
        std::vector<double> noise_times;
        std::vector<double> enc_times;
        p.TestEncryption(true, MAX_CTEXTS_DEFAULT, noise_times, enc_times);

        p.TestDecryption();
        
        p.TestEncryption(1, MAX_CTEXTS_DEFAULT, noise_times, enc_times);


        p.TestDecryption();
        */


        PSACryptocontext pp = PSACryptocontext(plain_bits, packing_size, MAX_CTEXTS_DEFAULT, iters, MS);

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

