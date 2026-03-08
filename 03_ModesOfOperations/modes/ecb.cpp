#include "ecb.hpp"

#include <iostream>
#include <string>
#include <limits>

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

/*  ======================
*   ECB Weakness Demo
*   ====================== */

void ecb_demo()
{
    std::string demo_plain =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 48 A's (3 identical blocks)

    std::string demo_key = "0123456789012345";

    std::vector<uint8_t> data(demo_plain.begin(), demo_plain.end());
    std::vector<uint8_t> key(demo_key.begin(), demo_key.end());

    auto result = ecb_encrypt(data, key);

    std::cout << "\nECB Weakness Demonstration\n";
    std::cout << "Plaintext: " << demo_plain << "\n";
    std::cout << "Key: " << demo_key << "\n\n";

    std::cout << "Plaintext blocks:\n";
    for (size_t i = 0; i < demo_plain.size(); i += AES_BLOCK_SIZE)
    {
        std::cout << "Block " << (i / AES_BLOCK_SIZE) + 1 << ": "
                  << demo_plain.substr(i, AES_BLOCK_SIZE) << "\n";
    }

    std::cout << "\nCiphertext blocks:\n";

    std::string hex = bytes_to_hex(result);

    for (size_t i = 0; i < hex.size(); i += 32)
    {
        std::cout << "Block " << (i / 32) + 1 << ": "
                  << hex.substr(i, 32) << "\n";
    }

    std::cout << "\nObservation: identical plaintext blocks produce identical ciphertext blocks.\n";
}


/* ======================
   ECB Mode Interface
   ====================== */

void ecb_mode()
{
    int op;
    std::cout << "\nECB Mode\n";
    std::cout << "1. Encrypt\n2. Decrypt\n3. Show ECB Weakness Demo\n";
    std::cin >> op;

    if (op == 3)
    {
        ecb_demo();
        return;
    }

    // This is required to not get an empty space insert in input.
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

    std::vector<uint8_t> data;

    if (op == 1)
        data = std::vector<uint8_t>(input.begin(), input.end());
    else
        data = hex_to_bytes(input);
    
    std::vector<uint8_t> key(key_str.begin(), key_str.end());

    std::vector<uint8_t> result;

    if (op == 1)
        result = ecb_encrypt(data, key);
    else
        result = ecb_decrypt(data, key);

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