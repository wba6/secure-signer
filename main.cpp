#include "RSAClient.hpp"
#include "gmp.h"
#include <iostream>

int main() {
    RSAClient client;
    RSAClient client2;

    std::string message = "Hello, World!",message2;

    mpz_class encryptedMessage;
    client.encrypt(message, encryptedMessage);
    auto publicKey = client.getPublicKey();
    client2.decrypt(encryptedMessage, message2, publicKey);

    std::cout << "\n" << message2 << std::endl;
    return 0;
}
