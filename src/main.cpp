#include "cmd_options.h"
#include "crypto_guard_ctx.h"

#include <array>
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
            return 0;
        }

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT: {
            std::ifstream inputFile(options.GetInputFile());
            std::ofstream outputFile(options.GetOutputFile());
            std::stringstream inputSstream, outputSstream;
            inputSstream << inputFile.rdbuf();
            try {
                cryptoCtx.EncryptFile(inputSstream, outputSstream, options.GetPassword());
            } catch (...) {
                std::print("Failed to encode file");
            }
            std::print("File encoded successfully. Result: {}", outputSstream.str());
            outputFile << outputSstream.rdbuf();
            break;
        }
        case COMMAND_TYPE::DECRYPT: {
            std::ifstream inputFile(options.GetInputFile());
            std::ofstream outputFile(options.GetOutputFile());
            std::stringstream inputSstream, outputSstream;
            inputSstream << inputFile.rdbuf();
            try {
                cryptoCtx.DecryptFile(inputSstream, outputSstream, options.GetPassword());
            } catch (...) {
                std::print("Failed to decode file");
            }
            std::print("File decoded successfully. Result: {}", outputSstream.str());
            outputFile << outputSstream.rdbuf();
            break;
        }
        case COMMAND_TYPE::CHECKSUM: {
            std::ifstream inputFile(options.GetInputFile());
            std::stringstream inputSstream;
            inputSstream << inputFile.rdbuf();
            try {
                std::print("Checksum: {}\n", cryptoCtx.CalculateChecksum(inputSstream));
            } catch (...) {
                std::print("Failed to calculate checksum");
            }
            break;
        }

        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}
