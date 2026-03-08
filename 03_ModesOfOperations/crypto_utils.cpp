#include "crypto_utils.hpp"
#include <stdexcept>

/* ===================================
*   XOR operation of equal block size
*  =================================== */

std::vector<uint8_t> xor_blocks(
    const std::vector<uint8_t>& first_block,
    const std::vector<uint8_t>& second_block
)
{
    if (first_block.size() != second_block.size())
        throw std::invalid_argument("Blocks must be of equal size for XOR.");

    std::vector<uint8_t> result(first_block.size());

    for (size_t i = 0; i < first_block.size(); ++i)
        result[i] = first_block[i] ^ second_block[i];

    return result;
}


/* =======================
*   Padding related code
========================= */

std::vector<uint8_t> pkcs7_pad(
    const std::vector<uint8_t>& data,
    size_t block_size
)
{
    if (block_size == 0)
        throw std::invalid_argument("Block size must be greater than zero.");

    size_t padding_len = block_size - (data.size() % block_size);

    if (padding_len == 0)
        padding_len = block_size;

    std::vector<uint8_t> padded = data;

    for (size_t i = 0; i < padding_len; ++i)
        padded.push_back(static_cast<uint8_t>(padding_len));

    return padded;
}


std::vector<uint8_t> pkcs7_unpad(
    const std::vector<uint8_t>& data
)
{
    if (data.empty())
        throw std::invalid_argument("Input data cannot be empty.");

    uint8_t padding_len = data.back();

    if (padding_len == 0 || padding_len > data.size())
        throw std::invalid_argument("Invalid PKCS7 padding.");

    for (size_t i = data.size() - padding_len; i < data.size(); ++i)
    {
        if (data[i] != padding_len)
            throw std::invalid_argument("Invalid PKCS7 padding.");
    }

    return std::vector<uint8_t>(data.begin(), data.end() - padding_len);
}


/* =====================
*   Block Handling
*  ===================== */

std::vector<std::vector<uint8_t>> split_blocks(
    const std::vector<uint8_t>& data,
    size_t block_size
)
{
    if (data.size() % block_size != 0)
        throw std::invalid_argument("Data size must be multiple of block size.");

    std::vector<std::vector<uint8_t>> blocks;

    for (size_t i = 0; i < data.size(); i += block_size)
    {
        blocks.emplace_back(
            data.begin() + i,
            data.begin() + i + block_size
        );
    }

    return blocks;
}


std::vector<uint8_t> merge_blocks(
    const std::vector<std::vector<uint8_t>>& blocks
)
{
    std::vector<uint8_t> data;

    for (const auto& block : blocks)
    {
        data.insert(
            data.end(),
            block.begin(),
            block.end()
        );
    }

    return data;
}


/* ======================
*   Validation Helpers
*  ====================== */

void validate_block_size(const std::vector<uint8_t>& block)
{
    if (block.size() != AES_BLOCK_SIZE)
        throw std::invalid_argument("Invalid AES block size.");
}