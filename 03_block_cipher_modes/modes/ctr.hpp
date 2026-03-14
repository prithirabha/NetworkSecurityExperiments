#ifndef CTR_HPP
#define CTR_HPP

#include <vector>
#include <cstdint>

/* ======================
   CTR Encryption
   ====================== */

std::vector<uint8_t> ctr_encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce
);

/* ======================
   CTR Decryption
   ====================== */

std::vector<uint8_t> ctr_decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce
);

/* ======================
   CTR Mode Interface
   ====================== */

void ctr_mode();

#endif