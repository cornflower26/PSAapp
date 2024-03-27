//
// Created by Antonia Januszewicz on 3/27/24.
//

#ifndef OPENFHE_PSA_CONSTANTS_H
#define OPENFHE_PSA_CONSTANTS_H

enum Scheme{NS, MS};

struct SLAPparams{
    unsigned int N, t, n, q, seed;
    Scheme sc;
    //May need some OpenFHE things here too
};


#endif  //OPENFHE_PSA_CONSTANTS_H
