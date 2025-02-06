/*
*   interface for the RSA client class
*
*   William Aey
*/

#ifndef RSACLIENT_HPP
#define RSACLIENT_HPP
#include <gmp.h>


class RSAClient {
public:
    RSAClient();
    ~RSAClient();

    void encrypt(std::string& message, mpz_t& returnVal);
    void decrypt(mpz_t& message, std::string& returnVal);
private:
    void generatePrime(mpz_t& returnVal);
    void generatePrivateKey(mpz_t& returnVal);
    void generatePublicKey(mpz_t& returnVal);

    void saveKeysToFile(std::string& filename);
private:
    mpz_t p;
    mpz_t q;
};

#endif // RSACLIENT_HPP
