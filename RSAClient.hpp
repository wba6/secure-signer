/*
*   interface for the RSA client class
*
*   William Aey
*/

#ifndef RSACLIENT_HPP
#define RSACLIENT_HPP
#include <gmpxx.h>

struct RSAKey {
    mpz_class& a;
    mpz_class& b;
};

class RSAClient {
public:
    RSAClient();
    ~RSAClient();

    void encrypt(std::string& message, mpz_class& returnVal);
    void decrypt(mpz_class& message, std::string& returnVal);
private:
    void generateKeys();

    void generateEValue(mpz_class& returnVal);
    void genPrime(mpz_class& returnVal);
    bool fermatTest(const mpz_class n, int iterations = 10);
    void saveKeysToFile(std::string& filename);
private:
    mpz_class m_p;
    mpz_class m_q;
    mpz_class m_n;
    mpz_class m_e;
    mpz_class m_d;
    mpz_class m_phi;
    RSAKey m_publicKey;
    RSAKey m_privateKey;
};

#endif // RSACLIENT_HPP
