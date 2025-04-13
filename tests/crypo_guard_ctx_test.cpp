#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <print>
#include <stdexcept>

TEST(CryptoGuard, TestEncrypt) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inputSstream("Hello world"), outputSstream;
    std::string password = "123";
    cryptoCtx.EncryptFile(inputSstream, outputSstream, password);
    EXPECT_EQ(outputSstream.eof(), false);
}

TEST(CryptoGuard, TestChecksum) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inputSstream("Hello world"), outputSstream;
    std::string password = "123";
    cryptoCtx.CalculateChecksum(inputSstream);
    EXPECT_EQ(outputSstream.eof(), false);
}