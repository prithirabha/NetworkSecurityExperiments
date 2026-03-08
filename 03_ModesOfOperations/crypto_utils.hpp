// If not defined.
#ifndef CRYPTO_UTILS_HPP
#define CRYPTO_UTILS_HPP

#include <vector>
#include <cstdint> // For using fixed sized integer types.

// Declare AES block size to remain constant/fixed throughout.
constexpr size_t AES_BLOCK_SIZE = 16; 

/* ===================================
*   XOR operation of equal block size
*  =================================== */

std::vector<uint8_t> xor_blocks(
    const std::vector<uint8_t>& first_block,
    const std::vector<uint8_t>& second_block
);

/* =======================
*   Padding related code
========================= */

std::vector<uint8_t> pkcs7_pad(
    const std::vector<uint8_t>& data,
    size_t block_size = AES_BLOCK_SIZE
);

std::vector<uint8_t> pkcs7_unpad(
    const std::vector<uint8_t>& data
);

/* =====================
*   Block Handling
*  ===================== */

std::vector<std::vector<uint8_t>> split_blocks(
    const std::vector<uint8_t>& data,
    size_t block_size = AES_BLOCK_SIZE
);

std::vector<uint8_t> merge_blocks(
    const std::vector<std::vector<uint8_t>>& blocks
);


/* ======================
*   Validation Helpers
*  ====================== */

void validate_block_size(const std::vector<uint8_t>& block);

#endif