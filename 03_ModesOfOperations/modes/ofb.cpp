#include "ofb.hpp"

#include <iostream>
#include <string>
#include <limits>

#include "../crypto_utils.hpp"
#include "../aes/aes_wrapper.hpp"


/* ======================
   OFB Encryption
   ====================== */

std::vector<uint8_t> ofb_encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv
)
{
    auto blocks = split_blocks(pkcs7_pad(plaintext));

    std::vector<std::vector<uint8_t>> encrypted_blocks;

    std::vector<uint8_t> feedback = iv;

    for (const auto& block : blocks)
    {
        // Generate keystream
        feedback = aes_encrypt_block(feedback, key);

        // XOR keystream with plaintext
        auto cipher = xor_blocks(block, feedback);

        encrypted_blocks.push_back(cipher);
    }

    return merge_blocks(encrypted_blocks);
}


/* ======================
   OFB Decryption
   ====================== */

std::vector<uint8_t> ofb_decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv
)
{
    auto blocks = split_blocks(ciphertext);

    std::vector<std::vector<uint8_t>> decrypted_blocks;

    std::vector<uint8_t> feedback = iv;

    for (const auto& block : blocks)
    {
        // Generate keystream
        feedback = aes_encrypt_block(feedback, key);

        // XOR with ciphertext
        auto plain = xor_blocks(block, feedback);

        decrypted_blocks.push_back(plain);
    }

    auto merged = merge_blocks(decrypted_blocks);

    return pkcs7_unpad(merged);
}


/* ======================
   OFB Mode Interface
   ====================== */

void ofb_mode()
{
    int op;

    std::cout << "\nOFB Mode\n";
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

        std::cout << "Error: Ciphertext length must be multiple of "
                  << AES_BLOCK_SIZE << " bytes.\n";
    }

    std::string key_str;

    while (true)
    {
        std::cout << "Enter 16-byte key: ";
        std::cin >> key_str;

        if (key_str.size() == AES_BLOCK_SIZE)
            break;
    }

    std::string iv_str;

    while (true)
    {
        std::cout << "Enter 16-byte IV: ";
        std::cin >> iv_str;

        if (iv_str.size() == AES_BLOCK_SIZE)
            break;
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
        result = ofb_encrypt(data, key, iv);
    else
        result = ofb_decrypt(data, key, iv);

    std::cout << "Result: ";

    if (op == 1)
        std::cout << bytes_to_hex(result);
    else
    {
        for (uint8_t b : result)
            std::cout << static_cast<char>(b);
    }

    std::cout << "\n";
}