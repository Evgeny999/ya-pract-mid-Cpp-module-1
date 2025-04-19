#include "crypto_guard_ctx.h"

#include <format>
#include <stdexcept>
#include <string.h>

#include <cstddef>
#include <iostream>
#include <memory>
#include <openssl/evp.h>
#include <print>
#include <sstream>
#include <vector>

namespace CryptoGuard {

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

class CryptoGuardCtx::Impl {
public:
    Impl();
    ~Impl();
    Impl(const Impl &) = delete;
    Impl(Impl &&) noexcept = delete;
    Impl &operator=(const Impl &other) = delete;
    Impl &operator=(const Impl &&other) noexcept = delete;

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    void EncryptDecryptFileImpl(std::iostream &inStream, std::iostream &outStream, std::string_view password, int enc);
    std::string CalculateChecksum(std::iostream &inStream);

    AesCipherParams CreateChiperParamsFromPassword(std::string_view password);
};

void CryptoGuardCtx::Impl::EncryptDecryptFileImpl(std::iostream &inStream, std::iostream &outStream,
                                                  std::string_view password, int enc) {
    if (!inStream.good() && !outStream.good()) {
        throw std::runtime_error(std::format("Failed to {} file: io stream error", enc == 1 ? "encrypt" : "decrypt"));
    }

    std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })> ctx(
        EVP_CIPHER_CTX_new());

    std::string output;

    auto params = CreateChiperParamsFromPassword(password);
    params.encrypt = enc;

    if (EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt) ==
        0) {
        throw std::runtime_error(
            std::format("Failed to {} file: call EVP_CipherInit_ex failure", enc == 1 ? "encrypt" : "decrypt"));
    }

    inStream.ignore(std::numeric_limits<std::streamsize>::max());
    std::streamsize length = inStream.gcount();
    inStream.clear();  //  Since ignore will have set eof.
    inStream.seekg(0, std::ios_base::beg);
    std::vector<unsigned char> inBuf(length);

    inStream.read(reinterpret_cast<char *>(inBuf.data()), length);

    std::vector<unsigned char> outBuf(inBuf.size() + EVP_MAX_BLOCK_LENGTH);
    int outLen = 0;

    if (EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), inBuf.size()) == 0) {
        throw std::runtime_error(
            std::format("Failed to {} file: call EVP_CipherUpdate failure", enc == 1 ? "encrypt" : "decrypt"));
    }

    outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);

    if (EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen) == 0) {
        throw std::runtime_error(
            std::format("Failed to {} file: call EVP_CipherFinal_ex failure", enc == 1 ? "encrypt" : "decrypt"));
    }

    outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);
}

void CryptoGuardCtx::Impl::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    EncryptDecryptFileImpl(inStream, outStream, password, 1);
}

void CryptoGuardCtx::Impl::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    EncryptDecryptFileImpl(inStream, outStream, password, 0);
}

std::string CryptoGuardCtx::Impl::CalculateChecksum(std::iostream &inStream) {
    if (!inStream.good()) {
        throw std::runtime_error("Failed to calculate checksum: input stream failure");
    }
    std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *ctx) { EVP_MD_CTX_free(ctx); })> ctx(EVP_MD_CTX_new());

    inStream.ignore(std::numeric_limits<std::streamsize>::max());
    std::streamsize length = inStream.gcount();
    inStream.clear();  //  Since ignore will have set eof.
    inStream.seekg(0, std::ios_base::beg);
    std::vector<unsigned char> inBuf(length), outBuf(EVP_MAX_MD_SIZE);

    inStream.read(reinterpret_cast<char *>(inBuf.data()), length);

    int outLen = 0;
    unsigned int md_len = 0;

    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), NULL) == 0) {
        throw std::runtime_error("Failed to calculate checksum: call EVP_DigestInit_ex failure");
    }
    if (EVP_DigestUpdate(ctx.get(), inBuf.data(), inBuf.size()) == 0) {
        throw std::runtime_error("Failed to calculate checksum: call EVP_DigestUpdate failure");
    }
    if (EVP_DigestFinal_ex(ctx.get(), outBuf.data(), &md_len) == 0) {
        throw std::runtime_error("Failed to calculate checksum: call EVP_DigestFinal_ex failure");
    }

    std::stringstream outputSs;
    for (size_t i = 0; i < md_len; ++i) {
        outputSs << std::hex << static_cast<int>(outBuf[i]);
    }

    std::string output = outputSs.str();
    return output;
}

CryptoGuardCtx::Impl::Impl() { OpenSSL_add_all_algorithms(); }

CryptoGuardCtx::Impl::~Impl() { EVP_cleanup(); }

AesCipherParams CryptoGuardCtx::Impl::CreateChiperParamsFromPassword(std::string_view password) {
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

    int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                params.key.data(), params.iv.data());

    if (result == 0) {
        throw std::runtime_error{"Failed to create a key from password"};
    }

    return params;
}

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()){};

CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}
void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}
std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); }

}  // namespace CryptoGuard
