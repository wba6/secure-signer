/*
* Implementation of the RSAClient class and helper functions
*
* William Aey
*/

#include "RSAClient.hpp"
#include <ctime>
#include <gmp.h>
const uint PRIME_SIZE = 256;// size of the prime numbers in bits
RSAClient::RSAClient() {
    // initialize the gmp variables
    mpz_init(m_p);
    mpz_init(m_q);
    mpz_init(m_n);
    mpz_init(m_e);
    mpz_init(m_d);
    mpz_init(m_phi);
    // generate the prime numbers
    generateKeys();
}

RSAClient::~RSAClient() {
    // clear the gmp variables
    mpz_clear(m_p);
    mpz_clear(m_q);
    mpz_clear(m_n);
    mpz_clear(m_e);
    mpz_clear(m_d);
    mpz_clear(m_phi);
}

void RSAClient::generateKeys() {

    // generate the prime numbers
    genPrime(m_p);
    genPrime(m_q);

    mpz_out_str(stdout, 10, m_p);

    // calculate n
    mpz_mul(m_n, m_p, m_q);

    // calculate phi
    mpz_mul(m_phi, m_p-1, m_q-1);

    // calculate e
    generateEValue(m_e);

    // calculate d
    mpz_invert(m_d, m_e, m_phi);

    // set the keys
    m_publicKey.a = m_e;
}

void RSAClient::generateEValue(mpz_t& returnVal) {
    // generate a random number
    gmp_randstate_t state;
    gmp_randinit_default(state);
    unsigned long seed = time(nullptr);
    gmp_randseed_ui(state, seed);
    mpz_urandomb(returnVal, state, PRIME_SIZE);

    // check if the number is coprime with n
    mpz_t gcdResult;
    mpz_init(gcdResult);
    while (mpz_cmp_si(gcdResult,1)==0){
        mpz_urandomb(returnVal, state, PRIME_SIZE);
        mpz_gcd(gcdResult,returnVal, m_phi);
    }

    mpz_clear(gcdResult);
}

void RSAClient::genPrime(mpz_t& returnVal) {
    // generate primes p and q
        // 1. Initialize a GMP random state.
        gmp_randstate_t state;
        gmp_randinit_default(state);

        // 2. Seed the random number generator.
        //    Here we use the current time to seed the generator.
        unsigned long seed = time(nullptr);
        gmp_randseed_ui(state, seed);

        // 4. Generate a random number with a specified number of bits.
        mpz_urandomb(returnVal, state, PRIME_SIZE);

        // 5. Check if the number is prime
        while (!fermatTest(returnVal)) {
            mpz_urandomb(returnVal, state, PRIME_SIZE);
        }
}

// Fermat's test: returns false if candidate n is composite
bool RSAClient::fermatTest(const mpz_t n, int iterations) {
    // 1. Quick checks
    // n < 2 => not prime
    if (mpz_cmp_ui(n, 2) < 0) {
        return false;
    }
    // n == 2 => prime
    if (mpz_cmp_ui(n, 2) == 0) {
        return true;
    }
    // Even number > 2 => composite
    if (mpz_even_p(n)) {
        return false;
    }
    // 2. Initialize and seed GMP random state
    gmp_randstate_t randState;
    gmp_randinit_mt(randState);
    mpz_t seed;
    mpz_init(seed);
    // Seed with current time (for demonstration; in production use a better seed)
    mpz_set_ui(seed, static_cast<unsigned long>(std::time(nullptr)));
    gmp_randseed(randState, seed);
    mpz_clear(seed);

    // 3. Perform 'iterations' rounds of Fermat test
    for (int i = 0; i < iterations; i++) {
        // Create random 'a' in [2 .. n-2]
        mpz_t a, n_minus_2;
        mpz_init(a);
        mpz_init(n_minus_2);

        mpz_sub_ui(n_minus_2, n, 2);       // n - 2
        mpz_urandomm(a, randState, n_minus_2);
        mpz_add_ui(a, a, 2);              // ensure a >= 2

        // Compute a^(n-1) mod n
        mpz_t exponent, modResult;
        mpz_init(exponent);
        mpz_init(modResult);

        mpz_sub_ui(exponent, n, 1);       // exponent = n - 1
        mpz_powm(modResult, a, exponent, n);

        // If a^(n-1) mod n != 1 => n is definitely composite
        if (mpz_cmp_ui(modResult, 1) != 0) {
            mpz_clear(a);
            mpz_clear(n_minus_2);
            mpz_clear(exponent);
            mpz_clear(modResult);
            gmp_randclear(randState);
            return false;
        }

        mpz_clear(a);
        mpz_clear(n_minus_2);
        mpz_clear(exponent);
        mpz_clear(modResult);
    }

    // Clean up random state
    gmp_randclear(randState);

    // Passed all rounds => probably prime
    return true;
}
