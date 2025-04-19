#include "crypto_guard_ctx.h"
#include <cstddef>
#include <gtest/gtest.h>
#include <print>
#include <sstream>
#include <stdexcept>

TEST(CryptoGuard, TestEncryptDecrypt) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inputSstream("Hello world"), outputSstream, resultStream;
    std::string password = "123";
    cryptoCtx.EncryptFile(inputSstream, outputSstream, password);
    cryptoCtx.DecryptFile(outputSstream, resultStream, password);
    EXPECT_EQ(inputSstream.str(), resultStream.str());
}

TEST(CryptoGuard, TestEncryptApiStability) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inputSstream("Hello world"), outputSstream, lastOutputSstream;
    std::string password = "123";
    bool status = true;
    for (size_t i = 0; i < 10; i++) {
        std::stringstream outputSstream;
        cryptoCtx.EncryptFile(inputSstream, outputSstream, password);
        if (i > 0 && outputSstream.str() != lastOutputSstream.str()) {
            status = false;
            break;
        }
        inputSstream.clear();
        inputSstream.seekg(0, std::ios_base::beg);
        lastOutputSstream = std::stringstream();
        lastOutputSstream << outputSstream.rdbuf();
    }
    EXPECT_TRUE(status);
}

TEST(CryptoGuard, TestDecryptApiStability) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inputSstream("Hello world"), lastOutputSstream;
    std::string password = "123";

    {
        std::stringstream outputSstream;
        cryptoCtx.EncryptFile(inputSstream, outputSstream, password);
        inputSstream = std::stringstream();
        inputSstream << outputSstream.rdbuf();
    }

    bool status = true;
    for (size_t i = 0; i < 10; i++) {
        std::stringstream outputSstream;
        cryptoCtx.DecryptFile(inputSstream, outputSstream, password);
        if (i > 0 && outputSstream.str() != lastOutputSstream.str()) {
            status = false;
            break;
        }
        inputSstream.clear();
        inputSstream.seekg(0, std::ios_base::beg);
        lastOutputSstream = std::stringstream();
        lastOutputSstream << outputSstream.rdbuf();
    }
    EXPECT_TRUE(status);
}

TEST(CryptoGuard, TestChecksum) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inputSstream("Hello world"), outputSstream;
    std::string password = "123";
    cryptoCtx.CalculateChecksum(inputSstream);
    EXPECT_EQ(outputSstream.eof(), false);
}