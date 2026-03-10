#ifndef CBC_HPP
#define CBC_HPP

#include <vector>
#include <cstdint>

/* ======================
   CBC Encryption
   ====================== */

std::vector<uint8_t> cbc_encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv
);


/* ======================
   CBC Decryption
   ====================== */

std::vector<uint8_t> cbc_decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv
);


/* ======================
   CBC Mode Interface
   ====================== */

void cbc_mode();

#endif