/*
*   interface for the RSA client class
*
*   William Aey
*/

#ifndef RSACLIENT_HPP
#define RSACLIENT_HPP
#include <gmpxx.h>
#include <utility>

class RSAClient {
public:
    RSAClient();
    ~RSAClient() = default;

    void sign(const std::string& fileName);
    bool checkSignature(const std::string& fileName, const std::pair<mpz_class,mpz_class>& publicKey);
    void encrypt(const std::string& message, mpz_class& returnVal, const std::pair<mpz_class,mpz_class>& publicKey);
    void decrypt(const mpz_class& message, std::string& returnVal);
    const std::pair<mpz_class,mpz_class>& getPublicKey() { return m_publicKey; };
private:
    void generateKeys();
    std::string loadFile(std::string filename);
    void generateEValue(mpz_class& returnVal);
    void genPrime(mpz_class& returnVal);
    bool fermatTest(const mpz_class n, int iterations = 1000);
    void savePrimesToFile(const char* filename);
    void saveKeyToFile(const char* filename, std::pair<mpz_class,mpz_class>& key);
private:
    mpz_class m_p;
    mpz_class m_q;
    mpz_class m_n;
    mpz_class m_e;
    mpz_class m_d;
    mpz_class m_phi;
    std::pair<mpz_class,mpz_class> m_publicKey;
    std::pair<mpz_class,mpz_class> m_privateKey;
    const uint PRIME_SIZE = 256;// size of the prime numbers in bits
};

#endif // RSACLIENT_HPP
