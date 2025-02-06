#include "RSAClient.hpp"
#include "gmp.h"
#include <iostream>

int main() {
    mpz_t my_large_integer;
    mpz_init(my_large_integer);
    RSAClient client;

    std::cout << "Hello, World!" << std::endl;
    return 0;
}
