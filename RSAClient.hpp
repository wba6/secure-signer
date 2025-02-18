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

public:
    RSAClient(bool generateKeys = true);
    ~RSAClient() = default;

    /*
    * sign a file by putting the encrypted hash of the file in the file
    *
    * @param fileName : the name of the file to sign
    */
    void sign(const std::string& fileName);

    /*
    * check the signature of a file
    *
    * @param fileName : the name of the file to check
    * @param publicKey : the public key to use to check the signature
    */
    bool checkSignature(const std::string& fileName, const std::pair<mpz_class,mpz_class>& publicKey);

    /*
    * get the public key
    *
    * @return : the public key
    */
    const std::pair<mpz_class,mpz_class>& getPublicKey() { return m_publicKey; };

private:
    /*
    * load the private key from a file
    */
    void loadPrivateKey();

    /*
    * load the public key from a file
    */
    void loadPublicKey();

    /*
    * save the prime numbers to a file
    *
    * @param filename : the name of the file to save to
    */
    void savePrimesToFile(const char* filename);

    /*
    * save the key to a file
    *
    * @param filename : the name of the file to save to
    * @param key : the key to save
    */
    void saveKeyToFile(const char* filename, std::pair<mpz_class,mpz_class>& key);

    /*
    * generate the keys need for RSA
    */
    void generateKeys();

    /*
    * generate a random number that is coprime with phi
    *
    * @param returnVal : the random number to return
    */
    void generateEValue(mpz_class& returnVal);

    /*
    * generate a prime number
    *
    * @param returnVal : the prime number to return
    */
    void genPrime(mpz_class& returnVal);

    /*
    * fermats little theorem test for primality
    *
    * @param n : the number to test
    * @param iterations : the number of iterations to run the test
    * @return : true if the number is probably prime, false if it is definitely composite
    */
    bool fermatTest(const mpz_class n, int iterations = 1000);

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
    bool modInvert(mpz_class &rop, const mpz_class &op1, const mpz_class &op2);

    /*
    * Helper function to load a file into a string
    *
    * @param filename : the name of the file to load
    * @return : the contents of the file as a string
    */
    std::string loadFile(std::string filename);
};

#endif // RSACLIENT_HPP
