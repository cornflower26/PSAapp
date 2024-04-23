//
// Created by Antonia Januszewicz on 4/16/24.
//

// Function to calculate the Hamming weight
unsigned int hammingWeight(unsigned int n) {
    unsigned int count = 0;
    while (n) {
        count += n & 1;
        n >>= 1;
    }
    return count;
}