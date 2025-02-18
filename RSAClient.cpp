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
#include <ostream>

// constructor
RSAClient::RSAClient(bool generateValues) {
    // generate the prime numbers
    if (generateValues) {
        generateKeys();
    } else {
        loadPublicKey();
        loadPrivateKey();
    }
}

/*
* load the public key from a file
*/
void RSAClient::loadPublicKey() {
    std::ifstream file("e_n.txt");
    std::string e, n;
    file >> e >> n;
    mpz_set_str(m_e.get_mpz_t(), e.c_str(), 10);
    mpz_set_str(m_n.get_mpz_t(), n.c_str(), 10);
    m_publicKey = std::make_pair(m_e, m_n);
}

/*
* load the private key from a file
*/
void RSAClient::loadPrivateKey() {
    std::ifstream file("d_n.txt");
    std::string d, n;
    file >> d >> n;
    mpz_set_str(m_d.get_mpz_t(), d.c_str(), 10);
    mpz_set_str(m_n.get_mpz_t(), n.c_str(), 10);
    m_privateKey = std::make_pair(m_d, m_n);
}

/*
* sign a file by putting the encrypted hash of the file in the file
*
* @param fileName : the name of the file to sign
*/
void RSAClient::sign(const std::string& fileName) {
    std::string hexMessage, fileContents = loadFile(fileName);
    picosha2::hash256_hex_string(fileContents, hexMessage);

    // convert the hex string to a number (base 16)
    mpz_class messageNum;
    if (mpz_set_str(messageNum.get_mpz_t(), hexMessage.c_str(), 16) != 0) {
        throw std::runtime_error("Invalid hex string for encryption.");
    }

    // encrypt the message
    mpz_class signature;
    mpz_powm(signature.get_mpz_t(),
                 messageNum.get_mpz_t(),
                 m_privateKey.first.get_mpz_t(),
                 m_privateKey.second.get_mpz_t());

    //save signature to file
    std::string signedFileName = fileName + ".signed";
    std::ofstream file(signedFileName);
    std::string signatureStr = mpz_get_str(nullptr, 16, signature.get_mpz_t());

    //pad the signature to 128 characters
    while (signatureStr.length() != 128 && signatureStr.length() < 128)
    {
        signatureStr = "0" + signatureStr;
    }

    //write the file contents and the signature to the file
    file << fileContents << signatureStr;
    file.close();
}

/*
* check the signature of a file
*
* @param fileName : the name of the file to check
* @param publicKey : the public key to use to check the signature
*/
bool RSAClient::checkSignature(const std::string& fileName, const std::pair<mpz_class,mpz_class>& publicKey) {
    std::string hexMessage, fileContentsSigned = loadFile(fileName);
    uint SIGNATURE_SIZE = 128;

    //split the file contents into the file contents and the signature
    std::string fileContents = fileContentsSigned.substr(0,fileContentsSigned.length()-(SIGNATURE_SIZE));
    std::string signatureStr = fileContentsSigned.substr(fileContentsSigned.length()-(SIGNATURE_SIZE),SIGNATURE_SIZE);

    // hash the file contents to be compared to the decrypted signature
    picosha2::hash256_hex_string(fileContents, hexMessage);

    // convert the hex string to a number (base 16)
    mpz_class signatureNum;
    if (mpz_set_str(signatureNum.get_mpz_t(), signatureStr.c_str(), 16) != 0) {
        throw std::runtime_error("Invalid hex string for encryption.");
    }

    // decrypt the signature
    mpz_class decryptedSignature;
    mpz_powm(decryptedSignature.get_mpz_t(),
                 signatureNum.get_mpz_t(),
                 publicKey.first.get_mpz_t(),
                 publicKey.second.get_mpz_t());

    return mpz_get_str(nullptr, 16, decryptedSignature.get_mpz_t()) == hexMessage;
}

/*
* save the prime numbers to a file
*
* @param filename : the name of the file to save to
*/
void RSAClient::savePrimesToFile(const char* filename){
    std::ofstream file(filename);

    file << m_p.get_str() << std::endl;
    file << m_q.get_str() << std::endl;

    file.close();
}

/*
* save the key to a file
*
* @param filename : the name of the file to save to
* @param key : the key to save
*/
void RSAClient::saveKeyToFile(const char* filename, std::pair<mpz_class,mpz_class>& key){
    std::ofstream file(filename);

    file << key.first.get_str() << std::endl;
    file << key.second.get_str() << std::endl;

    file.close();
}

/*
* generate the keys need for RSA
*/
void RSAClient::generateKeys() {

    // generate the prime numbers
    genPrime(m_p);
    genPrime(m_q);

    // calculate n
    m_n = m_p * m_q;

    // calculate phi
    m_phi = (m_p-1) * (m_q-1);

    // calculate e
    generateEValue(m_e);

    // calculate d
    modInvert(m_d, m_e, m_phi);

    // set the keys
    m_publicKey = std::make_pair(m_e, m_n);
    m_privateKey = std::make_pair(m_d, m_n);

    savePrimesToFile("p_q.txt");
    saveKeyToFile("e_n.txt", m_publicKey);
    saveKeyToFile("d_n.txt", m_privateKey);
}

/*
* generate a random number that is coprime with phi
*
* @param returnVal : the random number to return
*/
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

/*
* generate a prime number
*
* @param returnVal : the prime number to return
*/
void RSAClient::genPrime(mpz_class& returnVal) {
    // generate primes p and q
    gmp_randstate_t state;
    gmp_randinit_default(state);

    // Use the current time to seed the generator.
    unsigned long seed = static_cast<unsigned long>(std::chrono::system_clock::now().time_since_epoch().count());
    gmp_randseed_ui(state, seed);

    // Generate a random number with a specified number of bits.
    mpz_urandomb(returnVal.get_mpz_t(), state, PRIME_SIZE);

    // Check if the number is prime
    while (!fermatTest(returnVal)) {
        mpz_urandomb(returnVal.get_mpz_t(), state, PRIME_SIZE);
    }
}

/*
* fermats little theorem test for primality
*
* @param n : the number to test
* @param iterations : the number of iterations to run the test
* @return : true if the number is probably prime, false if it is definitely composite
*/
bool RSAClient::fermatTest(const mpz_class n, int iterations) {
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
    // Initialize and seed GMP random state
    gmp_randstate_t randState;
    gmp_randinit_mt(randState);
    unsigned long seed = static_cast<unsigned long>(std::chrono::system_clock::now().time_since_epoch().count());
    gmp_randseed_ui(randState, seed);

    // 'iterations' rounds of Fermat test
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

/*
 * Computes the modular inverse of op1 modulo op2.
 *
 * This function implements the extended Euclidean algorithm.
 *
 * @param rop : the result of the modular inverse
 * @param op1 : the number to invert
 * @param op2 : the modulus
 *
 * @return : true if the inverse exists, false otherwise
 */
bool RSAClient::modInvert(mpz_class &rop, const mpz_class &op1, const mpz_class &op2) {
    // Initialize remainders and coefficients:
    mpz_class r0 = op1, r1 = op2;
    mpz_class s0 = 1, s1 = 0;
    mpz_class quotient, temp;

    // Extended Euclidean algorithm loop:
    while (r1 != 0) {
        quotient = r0 / r1;

        // Update remainders: (r0, r1) = (r1, r0 - quotient * r1)
        temp = r1;
        r1 = r0 - quotient * r1;
        r0 = temp;

        // Update coefficients: (s0, s1) = (s1, s0 - quotient * s1)
        temp = s1;
        s1 = s0 - quotient * s1;
        s0 = temp;
    }

    // If gcd(op1, op2) is not 1, the inverse does not exist.
    if (r0 != 1)
        return false;

    // The modular inverse is s0, adjusted to be positive.
    rop = s0 % op2;
    if (rop < 0)
        rop += op2;

    return true;
}

/*
* Helper function to load a file into a string
*
* @param filename : the name of the file to load
* @return : the contents of the file as a string
*/
std::string RSAClient::loadFile(std::string filename){
    std::ifstream t(filename);
    if (!t) {
        throw std::runtime_error("Error: File \"" + filename + "\" does not exist or cannot be opened.");
    }
    std::stringstream buffer;
    buffer << t.rdbuf();
    return (buffer.str());
}
