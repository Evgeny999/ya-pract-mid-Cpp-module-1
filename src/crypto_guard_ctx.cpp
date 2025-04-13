#include "crypto_guard_ctx.h"

#include <cstddef>
#include <iostream>
#include <memory>
#include <openssl/evp.h>
#include <print>
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

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    void EncryptDecryptFileImpl(std::iostream &inStream, std::iostream &outStream, std::string_view password, int enc);
    std::string CalculateChecksum(std::iostream &inStream) { return "NOT_IMPLEMENTED"; }

    AesCipherParams CreateChiperParamsFromPassword(std::string_view password);

private:
    std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx_) { EVP_CIPHER_CTX_free(ctx_); })> ctx_;
};

void CryptoGuardCtx::Impl::EncryptDecryptFileImpl(std::iostream &inStream, std::iostream &outStream,
                                                  std::string_view password, int enc) {
    if (!inStream.good() && !outStream.good()) {
        throw;
    }

    std::string output;

    auto params = CreateChiperParamsFromPassword(password);
    params.encrypt = enc;

    // Инициализируем cipher
    EVP_CipherInit_ex(ctx_.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt);

    std::vector<unsigned char> inBuf;
    char c;
    while (inStream.get(c)) {
        inBuf.push_back(c);
    }
    std::vector<unsigned char> outBuf(inBuf.size() + EVP_MAX_BLOCK_LENGTH);
    int outLen;

    // Обрабатываем первые N символов
    EVP_CipherUpdate(ctx_.get(), outBuf.data(), &outLen, inBuf.data(), inBuf.size());
    for (int i = 0; i < outLen; ++i) {
        output.push_back(outBuf[i]);
    }

    // Обрабатываем оставшиеся символы
    /*EVP_CipherUpdate(ctx_.get(), outBuf.data(), &outLen, inBuf.data(), inBuf.size());
    for (int i = 0; i < outLen; ++i) {
        output.push_back(outBuf[i]);
    }*/

    // Заканчиваем работу с cipher
    EVP_CipherFinal_ex(ctx_.get(), outBuf.data(), &outLen);
    for (int i = 0; i < outLen; ++i) {
        output.push_back(outBuf[i]);
    }
    // std::print("String encoded successfully. Result: '{}'\n\n", output);
    outStream << output;
}

void CryptoGuardCtx::Impl::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    EncryptDecryptFileImpl(inStream, outStream, password, 1);
}

void CryptoGuardCtx::Impl::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    EncryptDecryptFileImpl(inStream, outStream, password, 0);
}

CryptoGuardCtx::Impl::Impl() : ctx_(EVP_CIPHER_CTX_new()) { OpenSSL_add_all_algorithms(); }

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
