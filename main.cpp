#include "RSAClient.hpp"
#include <iostream>

int main() {
    RSAClient client;

    std::pair<mpz_class,mpz_class> publicKey = client.getPublicKey();

    client.sign("testFile.txt");
    if (client.checkSignature("testFile.txt.signed", publicKey)) {
        std::cout << "Signature is valid!" << std::endl;
    } else {
        std::cout << "Signature is invalid!" << std::endl;
    }

    return 0;
}
