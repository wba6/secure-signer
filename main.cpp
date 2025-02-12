#include "RSAClient.hpp"
#include "gmp.h"
#include <iostream>

int main() {
    RSAClient client;

    std::string message = "H",message2;

    mpz_class encryptedMessage;
    auto publicKey = client.getPublicKey();
    client.encrypt(message, encryptedMessage,publicKey);
    client.decrypt(encryptedMessage, message2);

    std::cout << "\nMessage: " << message2 << std::endl;
    return 0;
}
