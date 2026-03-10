#ifndef CFB_HPP
#define CFB_HPP

#include <vector>
#include <cstdint>

/* ======================
   CFB Encryption
   ====================== */

std::vector<uint8_t> cfb_encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv
);


/* ======================
   CFB Decryption
   ====================== */

std::vector<uint8_t> cfb_decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv
);


/* ======================
   CFB Mode Interface
   ====================== */

void cfb_mode();

#endif