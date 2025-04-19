#include "cmd_options.h"
#include "crypto_guard_ctx.h"

#include <array>
#include <exception>
#include <fstream>
#include <iostream>
#include <istream>
#include <openssl/evp.h>
#include <print>
#include <sstream>
#include <stdexcept>
#include <string>

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        if (!options.Parse(argc, argv)) {
            return 1;
        }

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT: {
            std::fstream inputFile(options.GetInputFile(), std::fstream::in);
            std::fstream outputFile(options.GetOutputFile(), std::fstream::out);
            cryptoCtx.EncryptFile(inputFile, outputFile, options.GetPassword());
            std::print("File encoded successfully");
            break;
        }
        case COMMAND_TYPE::DECRYPT: {
            std::fstream inputFile(options.GetInputFile(), std::fstream::in);
            std::fstream outputFile(options.GetOutputFile(), std::fstream::out);
            cryptoCtx.DecryptFile(inputFile, outputFile, options.GetPassword());
            std::print("File decoded successfully");
            break;
        }
        case COMMAND_TYPE::CHECKSUM: {
            std::fstream inputFile(options.GetInputFile(), std::fstream::in);
            std::print("Checksum: {}\n", cryptoCtx.CalculateChecksum(inputFile));
            break;
        }

        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 2;
    }

    return 0;
}
