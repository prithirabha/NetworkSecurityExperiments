#include "ecb.hpp"

#include <iostream>
#include <string>

#include "../crypto_utils.hpp"
#include "../aes/aes_wrapper.hpp"

/* ======================
   ECB Encryption
   ====================== */

std::vector<uint8_t> ecb_encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key
)
{
    std::vector<uint8_t> padded = pkcs7_pad(plaintext);

    auto blocks = split_blocks(padded);

    std::vector<std::vector<uint8_t>> encrypted_blocks;

    for (const auto& block : blocks)
    {
        encrypted_blocks.push_back(
            aes_encrypt_block(block, key)
        );
    }

    return merge_blocks(encrypted_blocks);
}

/* ======================
   ECB Decryption
   ====================== */

std::vector<uint8_t> ecb_decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key
)
{
    auto blocks = split_blocks(ciphertext);

    std::vector<std::vector<uint8_t>> decrypted_blocks;

    for (const auto& block : blocks)
    {
        decrypted_blocks.push_back(
            aes_decrypt_block(block, key)
        );
    }

    std::vector<uint8_t> merged = merge_blocks(decrypted_blocks);

    return pkcs7_unpad(merged);
}

/* ======================
   ECB Mode Interface
   ====================== */

void ecb_mode()
{
    int op;
    std::cout << "\nECB Mode\n";
    std::cout << "1. Encrypt\n2. Decrypt\n";
    std::cin >> op;

    std::string input;
    while (true)
    {
        std::cout << "Enter text: ";
        std::cin >> input;

        data = std::vector<uint8_t>(input.begin(), input.end());

        if (op == 1)   // encryption always allowed
            break;

        if (data.size() % AES_BLOCK_SIZE == 0)
            break;

        std::cout << "Error: Ciphertext length must be a multiple of "
                << AES_BLOCK_SIZE << " bytes.\n";
        std::cout << "Please try again.\n";
    }

    std::string key_str;

    while (true)
    {
        std::cout << "Enter 16-byte key: ";
        std::cin >> key_str;

        if (key_str.size() == AES_BLOCK_SIZE)
            break;

        std::cout << "Invalid key length. AES-128 requires exactly "
                  << AES_BLOCK_SIZE << " bytes.\n";
        std::cout << "Please try again.\n";
    }

    std::vector<uint8_t> data(input.begin(), input.end());
    std::vector<uint8_t> key(key_str.begin(), key_str.end());

    std::vector<uint8_t> result;

    if (op == 1)
        result = ecb_encrypt(data, key);
    else
        result = ecb_decrypt(data, key);

    std::cout << "Result: ";

    for (uint8_t b : result)
        std::cout << static_cast<char>(b);

    std::cout << "\n";
}