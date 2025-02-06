/*
*   interface for the RSA client class
*
*   William Aey
*/

#ifndef RSACLIENT_HPP
#define RSACLIENT_HPP
#include <gmpxx.h>


class RSAClient {
public:
    RSAClient();
    ~RSAClient();

    void encrypt(std::string& message, mpz_t& returnVal);
    void decrypt(mpz_t& message, std::string& returnVal);
private:
    void generatePrimes();
    void generatePrime(mpz_t& returnVal);

    bool fermatTest(const mpz_t n, int iterations = 10);
    void saveKeysToFile(std::string& filename);
private:
    mpz_t m_p;
    mpz_t m_q;
};

#endif // RSACLIENT_HPP
