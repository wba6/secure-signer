#include "gmpxx.h"
#include <iostream>

int main() {
    mpz_t my_large_integer;
    mpz_init(my_large_integer);
    std::cout << "Hello, World!" << std::endl;
    return 0;
}
