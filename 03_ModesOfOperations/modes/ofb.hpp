#ifndef OFB_HPP
#define OFB_HPP

#include <vector>
#include <cstdint>

/* ======================
   OFB Encryption
   ====================== */

std::vector<uint8_t> ofb_encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv
);

/* ======================
   OFB Decryption
   ====================== */

std::vector<uint8_t> ofb_decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv
);

/* ======================
   OFB Mode Interface
   ====================== */

void ofb_mode();

#endif