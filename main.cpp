#include "RSAClient.hpp"
#include <iostream>
#include "PicoSHA2/picosha2.h"

int main() {
    RSAClient client;

    std::string message = "Hello world",message2;

    std::string hash_hex_str;
    picosha2::hash256_hex_string(message, hash_hex_str);

    mpz_class encryptedMessage;
    auto publicKey = client.getPublicKey();
    client.encrypt(hash_hex_str, encryptedMessage,publicKey);

    std::cout << "\nEncrypted message: ";
    mpz_out_str(stdout, 10, encryptedMessage.get_mpz_t());
    std::cout << "\n";

    client.decrypt(encryptedMessage, message2);

    if (hash_hex_str == message2) {
        std::cout << "Success! The message was encrypted and decrypted successfully." << std::endl;
    } else {
        std::cout << "Error! The message was not encrypted and decrypted successfully." << std::endl;
    }

    std::cout << "\nMessage: " << message2 << std::endl;
    return 0;
}
