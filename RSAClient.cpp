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
    // generate the prime numbers
    generateKeys();
}

RSAClient::~RSAClient() {
}

void RSAClient::generateKeys() {

    // generate the prime numbers
    genPrime(m_p);
    genPrime(m_q);

    mpz_out_str(stdout, 10, m_p.get_mpz_t());

    // calculate n
    m_n = m_p * m_q;

    // calculate phi
    m_phi = (m_p-1) * (m_q-1);

    // calculate e
    generateEValue(m_e);

    // calculate d
    mpz_invert(m_d.get_mpz_t(), m_e.get_mpz_t(), m_phi.get_mpz_t());

    // set the keys
    m_publicKey = std::make_pair(m_e, m_n);
    m_privateKey = std::make_pair(m_d, m_n);
}

void RSAClient::generateEValue(mpz_class& returnVal) {
    // generate a random number
    gmp_randstate_t state;
    gmp_randinit_default(state);
    unsigned long seed = time(nullptr);
    gmp_randseed_ui(state, seed);
    mpz_urandomb(returnVal.get_mpz_t(), state, PRIME_SIZE);

    // check if the number is coprime with n
    mpz_class gcdResult;
    while (gcdResult==1){
        mpz_urandomb(returnVal.get_mpz_t(), state, PRIME_SIZE);
        mpz_gcd(gcdResult.get_mpz_t(),returnVal.get_mpz_t(), m_phi.get_mpz_t());
    }

}

void RSAClient::genPrime(mpz_class& returnVal) {
    // generate primes p and q
        // 1. Initialize a GMP random state.
        gmp_randstate_t state;
        gmp_randinit_default(state);

        // 2. Seed the random number generator.
        //    Here we use the current time to seed the generator.
        unsigned long seed = time(nullptr);
        gmp_randseed_ui(state, seed);

        // 4. Generate a random number with a specified number of bits.
        mpz_urandomb(returnVal.get_mpz_t(), state, PRIME_SIZE);

        // 5. Check if the number is prime
        while (!fermatTest(returnVal)) {
            mpz_urandomb(returnVal.get_mpz_t(), state, PRIME_SIZE);
        }
}

// Fermat's test: returns false if candidate n is composite
bool RSAClient::fermatTest(const mpz_class n, int iterations) {
    // 1. Quick checks
    // n < 2 => not prime
    if (n < 2) {
        return false;
    }
    // n == 2 => prime
    if (n == 0) {
        return true;
    }
    // Even number > 2 => composite
    if (mpz_even_p(n.get_mpz_t())) {
        return false;
    }
    // 2. Initialize and seed GMP random state
    gmp_randstate_t randState;
    gmp_randinit_mt(randState);
    mpz_class seed;
    // Seed with current time (for demonstration; in production use a better seed)
    mpz_set_ui(seed.get_mpz_t(), static_cast<unsigned long>(std::time(nullptr)));
    gmp_randseed(randState, seed.get_mpz_t());

    // 3. Perform 'iterations' rounds of Fermat test
    for (int i = 0; i < iterations; i++) {
        // Create random 'a' in [2 .. n-2]
        mpz_class a, n_minus_2;

        mpz_sub_ui(n_minus_2.get_mpz_t(), n.get_mpz_t(), 2);       // n - 2
        mpz_urandomm(a.get_mpz_t(), randState, n_minus_2.get_mpz_t());
        mpz_add_ui(a.get_mpz_t(), a.get_mpz_t(), 2);              // ensure a >= 2

        // Compute a^(n-1) mod n
        mpz_class exponent, modResult;

        mpz_sub_ui(exponent.get_mpz_t(), n.get_mpz_t(), 1);       // exponent = n - 1
        mpz_powm(modResult.get_mpz_t(), a.get_mpz_t(), exponent.get_mpz_t(), n.get_mpz_t());

        // If a^(n-1) mod n != 1 => n is definitely composite
        if (modResult != 1) {
            gmp_randclear(randState);
            return false;
        }

    }

    // Clean up random state
    gmp_randclear(randState);

    // Passed all rounds => probably prime
    return true;
}
