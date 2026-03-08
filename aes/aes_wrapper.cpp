#include "aes_wrapper.hpp"

#include <openssl/aes.h>
#include <stdexcept>

std::vector<uint8_t> aes_encrypt_block(
    const std::vector<uint8_t>& block,
    const std::vector<uint8_t>& key
)
{
    if (block.size() != AES_BLOCK_SIZE)
        throw std::invalid_argument("AES block must be 16 bytes");

    if (key.size() != AES_BLOCK_SIZE)
        throw std::invalid_argument("AES key must be 16 bytes (AES-128)");

    AES_KEY aes_key;
    AES_set_encrypt_key(key.data(), 128, &aes_key);

    std::vector<uint8_t> ciphertext(AES_BLOCK_SIZE);

    AES_encrypt(
        block.data(),
        ciphertext.data(),
        &aes_key
    );

    return ciphertext;
}

std::vector<uint8_t> aes_decrypt_block(
    const std::vector<uint8_t>& block,
    const std::vector<uint8_t>& key
)
{
    if (block.size() != AES_BLOCK_SIZE)
        throw std::invalid_argument("AES block must be 16 bytes");

    if (key.size() != AES_BLOCK_SIZE)
        throw std::invalid_argument("AES key must be 16 bytes (AES-128)");

    AES_KEY aes_key;
    AES_set_decrypt_key(key.data(), 128, &aes_key);

    std::vector<uint8_t> plaintext(AES_BLOCK_SIZE);

    AES_decrypt(
        block.data(),
        plaintext.data(),
        &aes_key
    );

    return plaintext;
}