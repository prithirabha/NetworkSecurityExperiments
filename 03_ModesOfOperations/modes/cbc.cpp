#include "cbc.hpp"

#include <iostream>
#include <string>
#include <limits>

#include "../crypto_utils.hpp"
#include "../aes/aes_wrapper.hpp"


/* ======================
   CBC Encryption
   ====================== */

std::vector<uint8_t> cbc_encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv
)
{
    std::vector<uint8_t> padded = pkcs7_pad(plaintext);

    auto blocks = split_blocks(padded);

    std::vector<std::vector<uint8_t>> encrypted_blocks;

    std::vector<uint8_t> prev = iv;

    for (const auto& block : blocks)
    {
        auto xored = xor_blocks(block, prev);

        auto cipher = aes_encrypt_block(xored, key);

        encrypted_blocks.push_back(cipher);

        prev = cipher;
    }

    return merge_blocks(encrypted_blocks);
}


/* ======================
   CBC Decryption
   ====================== */

std::vector<uint8_t> cbc_decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv
)
{
    auto blocks = split_blocks(ciphertext);

    std::vector<std::vector<uint8_t>> decrypted_blocks;

    std::vector<uint8_t> prev = iv;

    for (const auto& block : blocks)
    {
        auto decrypted = aes_decrypt_block(block, key);

        auto plain = xor_blocks(decrypted, prev);

        decrypted_blocks.push_back(plain);

        prev = block;
    }

    auto merged = merge_blocks(decrypted_blocks);

    return pkcs7_unpad(merged);
}


/* ======================
   CBC Mode Interface
   ====================== */

void cbc_mode()
{
    int op;

    std::cout << "\nCBC Mode\n";
    std::cout << "1. Encrypt\n2. Decrypt\n";
    std::cin >> op;

    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    std::string input;

    while (true)
    {
        std::cout << "Enter text: ";
        std::getline(std::cin, input);

        if (op == 1)
            break;

        if ((input.size() % 2 == 0) && ((input.size()/2) % AES_BLOCK_SIZE == 0))
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

    std::string iv_str;

    while (true)
    {
        std::cout << "Enter 16-byte IV: ";
        std::cin >> iv_str;

        if (iv_str.size() == AES_BLOCK_SIZE)
            break;

        std::cout << "Invalid IV length. Must be exactly "
                  << AES_BLOCK_SIZE << " bytes.\n";
        std::cout << "Please try again.\n";
    }

    std::vector<uint8_t> data;

    if (op == 1)
        data = std::vector<uint8_t>(input.begin(), input.end());
    else
        data = hex_to_bytes(input);

    std::vector<uint8_t> key(key_str.begin(), key_str.end());
    std::vector<uint8_t> iv(iv_str.begin(), iv_str.end());

    std::vector<uint8_t> result;

    if (op == 1)
        result = cbc_encrypt(data, key, iv);
    else
        result = cbc_decrypt(data, key, iv);

    std::cout << "Result: ";

    if (op == 1)
    {
        std::cout << bytes_to_hex(result);
    }
    else
    {
        for (uint8_t b : result)
            std::cout << static_cast<char>(b);
    }

    std::cout << "\n";
}