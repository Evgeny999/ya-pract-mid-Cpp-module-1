#include <gtest/gtest.h>

#include "cmd_options.h"

TEST(ProgramOptions, TestCmdEncrypt) {
    CryptoGuard::ProgramOptions options;
    int argc = 9;
    const char *argv[] = {"CryptoGuard", "-i",   "encrypted.txt", "-o",     "decrypted.txt",
                          "-p",          "1234", "--command",     "encrypt"};
    EXPECT_EQ(options.Parse(argc, const_cast<char **>(argv)), true);
}

TEST(ProgramOptions, TestCmdDecrypt) {
    CryptoGuard::ProgramOptions options;
    int argc = 9;
    const char *argv[] = {"CryptoGuard", "-i",   "encrypted.txt", "-o",     "decrypted.txt",
                          "-p",          "1234", "--command",     "decrypt"};
    EXPECT_EQ(options.Parse(argc, const_cast<char **>(argv)), true);
}

TEST(ProgramOptions, TestCmdChecksum) {
    CryptoGuard::ProgramOptions options;
    int argc = 5;
    const char *argv[] = {"CryptoGuard", "-i", "encrypted.txt", "--command", "checksum"};
    EXPECT_EQ(options.Parse(argc, const_cast<char **>(argv)), true);
}

TEST(ProgramOptions, TestCmdNoArgs) {
    CryptoGuard::ProgramOptions options;
    int argc = 1;
    const char *argv[] = {"CryptoGuard"};
    EXPECT_EQ(options.Parse(argc, const_cast<char **>(argv)), false);
}

TEST(ProgramOptions, TestCmdInvalidArgs) {
    CryptoGuard::ProgramOptions options;
    int argc = 2;
    const char *argv[] = {"CryptoGuard", "-abc"};
    EXPECT_EQ(options.Parse(argc, const_cast<char **>(argv)), false);
}

TEST(ProgramOptions, TestCmdMissingArgs) {
    CryptoGuard::ProgramOptions options;
    int argc = 8;
    const char *argv[] = {"CryptoGuard", "-i", "encrypted.txt", "-o", "-p", "1234", "--command", "encrypt"};
    EXPECT_EQ(options.Parse(argc, const_cast<char **>(argv)), false);
}