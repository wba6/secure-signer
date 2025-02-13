/*
* Implementation of the RSAClient class and helper functions
*
* William Aey
*/

#include <iostream>
#include "RSAClient.hpp"
#include "PicoSHA2/picosha2.h"
#include <chrono>
#include <gmp.h>
#include <fstream>
const uint PRIME_SIZE = 256;// size of the prime numbers in bits
RSAClient::RSAClient() {
    // generate the prime numbers
    generateKeys();
}

RSAClient::~RSAClient() {
}

void RSAClient::sign(const std::string& fileName) {
    std::string hexMessage, fileContents = loadFile(fileName);
    picosha2::hash256_hex_string(fileContents, hexMessage);

    mpz_class messageNum;
    if (mpz_set_str(messageNum.get_mpz_t(), hexMessage.c_str(), 16) != 0) {
        throw std::runtime_error("Invalid hex string for encryption.");
    }

    mpz_class signature;
    mpz_powm(signature.get_mpz_t(),
                 messageNum.get_mpz_t(),
                 m_privateKey.first.get_mpz_t(),
                 m_privateKey.second.get_mpz_t());

    //save signature to file
    std::string signedFileName = fileName + ".signed";
    std::ofstream file(signedFileName);
    file << fileContents << signature.get_str();
    file.close();
}

void RSAClient::encrypt(const std::string& hexMessage,
                        mpz_class& cipher,
                        const std::pair<mpz_class, mpz_class>& publicKey) {
    // Convert the hex string to a number (base 16)
    mpz_class messageNum;
    if (mpz_set_str(messageNum.get_mpz_t(), hexMessage.c_str(), 16) != 0) {
        throw std::runtime_error("Invalid hex string for encryption.");
    }

    std::cout << "Message as number: ";
    mpz_out_str(stdout, 10, messageNum.get_mpz_t());
    std::cout << std::endl;

    // Encrypt: cipher = messageNum^e mod n
    mpz_powm(cipher.get_mpz_t(),
             messageNum.get_mpz_t(),
             publicKey.first.get_mpz_t(),
             publicKey.second.get_mpz_t());
}

void RSAClient::decrypt(const mpz_class& cipher, std::string& hexMessageOut) {
    // Decrypt: decrypted = cipher^d mod n, using your stored private key (d, n)
    mpz_class decrypted;
    mpz_powm(decrypted.get_mpz_t(),
             cipher.get_mpz_t(),
             m_privateKey.first.get_mpz_t(),   // d
             m_privateKey.second.get_mpz_t()); // n

    std::cout << "Decrypted number: ";
    mpz_out_str(stdout, 10, decrypted.get_mpz_t());
    std::cout << std::endl;

    // Convert the decrypted number back to a hex string
    char* hexStr = mpz_get_str(nullptr, 16, decrypted.get_mpz_t());
    hexMessageOut = std::string(hexStr);
    free(hexStr); // mpz_get_str uses malloc() internally
}


void RSAClient::savePrimesToFile(const char* filename){
    std::ofstream file(filename);

    file << m_p.get_str() << std::endl;
    file << m_q.get_str() << std::endl;

    file.close();
}

void RSAClient::saveKeyToFile(const char* filename, std::pair<mpz_class,mpz_class>& key){
    std::ofstream file(filename);

    file << key.first.get_str() << std::endl;
    file << key.second.get_str() << std::endl;

    file.close();
}

void RSAClient::generateKeys() {

    // generate the prime numbers
    genPrime(m_p);
    genPrime(m_q);

    mpz_out_str(stdout, 10, m_p.get_mpz_t());
    std::cout << std::endl;

    mpz_out_str(stdout, 10, m_q.get_mpz_t());
    std::cout << std::endl;

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

    savePrimesToFile("p_q.txt");
    saveKeyToFile("e_n.txt", m_publicKey);
    saveKeyToFile("d_n.txt", m_privateKey);
}

void RSAClient::generateEValue(mpz_class& returnVal) {
    // generate a random number
    gmp_randstate_t state;
    gmp_randinit_default(state);
    unsigned long seed = static_cast<unsigned long>(std::chrono::system_clock::now().time_since_epoch().count());
    gmp_randseed_ui(state, seed);
    mpz_urandomb(returnVal.get_mpz_t(), state, PRIME_SIZE);

    // check if the number is coprime with n
    mpz_class gcdResult;
    while (gcdResult!=1){
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
        unsigned long seed = static_cast<unsigned long>(std::chrono::system_clock::now().time_since_epoch().count());
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
    unsigned long seed = static_cast<unsigned long>(std::chrono::system_clock::now().time_since_epoch().count());
    gmp_randseed_ui(randState, seed);

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

std::string RSAClient::loadFile(std::string filename){
    std::ifstream t(filename);
    std::stringstream buffer;
    buffer << t.rdbuf();
    return (buffer.str());
}
