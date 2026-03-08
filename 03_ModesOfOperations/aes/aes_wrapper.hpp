#ifndef AES_WRAPPER_HPP
#define AES_WRAPPER_HPP

#include <vector>
#include <cstdint>
#include "../crypto_utils.hpp"

std::vector<uint8_t> aes_encrypt_block(
    const std::vector<uint8_t>& block,
    const std::vector<uint8_t>& key
);

std::vector<uint8_t> aes_decrypt_block(
    const std::vector<uint8_t>& block,
    const std::vector<uint8_t>& key
);

#endif