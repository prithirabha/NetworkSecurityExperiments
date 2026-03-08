#ifndef ECB_HPP
#define ECB_HPP

#include <vector>
#include <cstdint>

std::vector<uint8_t> ecb_encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key
);

std::vector<uint8_t> ecb_decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key
);

void ecb_mode();

#endif