#include "RSAClient.hpp"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <keyParameter> [operation] [filename]" << std::endl;
        return 1;
    }

    // Convert first argument to an integer key parameter.
    int keyParameter = std::stoi(argv[1]);

    if (keyParameter == 1) {
        RSAClient client = RSAClient(true);
    } else if (keyParameter == 2) {
        RSAClient client = RSAClient(false);

        // Read operation and filename.
        char operation = argv[2][0];
        std::string filename = argv[3];

        if (operation == 's') {
            client.sign(filename);
        } else if (operation == 'v') {
            std::pair<mpz_class, mpz_class> publicKey = client.getPublicKey();
            if (client.checkSignature(filename, publicKey)) {
                std::cout << "Signature is valid!" << std::endl;
            } else {
                std::cout << "Signature is invalid!" << std::endl;
            }
        }
    }

    return 0;
}
