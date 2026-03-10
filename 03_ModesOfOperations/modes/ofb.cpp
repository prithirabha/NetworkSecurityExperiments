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

/* ===========================
   OFB Keystream Reuse Demo
   =========================== */

void ofb_keystream_demo()
{
    std::cout << "\n=== OFB Keystream Reuse Demo ===\n";

    std::string p1 = "attack at dawn!!!!";
    std::string p2 = "attack at dusk!!!!";

    std::string key_str = "0123456789012345";
    std::string iv_str  = "1234567890123456";

    std::vector<uint8_t> key(key_str.begin(), key_str.end());
    std::vector<uint8_t> iv(iv_str.begin(), iv_str.end());

    std::vector<uint8_t> data1(p1.begin(), p1.end());
    std::vector<uint8_t> data2(p2.begin(), p2.end());

    auto c1 = ofb_encrypt(data1, key, iv);
    auto c2 = ofb_encrypt(data2, key, iv);

    std::vector<uint8_t> x = xor_blocks(c1, c2);

    std::cout << "\nPlaintext1:\n" << p1 << "\n";
    std::cout << "\nPlaintext2:\n" << p2 << "\n";

    std::cout << "\nC1 XOR C2 (reveals P1 XOR P2):\n";

    std::cout << bytes_to_hex(x) << "\n";

    auto px = xor_blocks(data1, data2);

    std::cout << "\nC1 XOR C2:\n";
    std::cout << bytes_to_hex(x) << "\n";

    std::cout << "\nP1 XOR P2:\n";
    std::cout << bytes_to_hex(px) << "\n";

    std::cout << "\n";
}

/* ===========================
   OFB Bit-Flipping Attack Demo
   =========================== */

void ofb_bitflip_demo()
{
    std::cout << "\n=== OFB Bit-Flipping Attack Demo ===\n";

    std::string plaintext = "role=user;access=limited;";

    std::string key_str = "0123456789012345";
    std::string iv_str  = "1234567890123456";

    std::vector<uint8_t> key(key_str.begin(), key_str.end());
    std::vector<uint8_t> iv(iv_str.begin(), iv_str.end());
    std::vector<uint8_t> data(plaintext.begin(), plaintext.end());

    auto ciphertext = ofb_encrypt(data, key, iv);

    std::cout << "\nOriginal plaintext:\n";
    std::cout << plaintext << "\n";

    /* --------------------------------------------------
       OFB malleability

       Pi = Ci XOR Oi

       Modifying Ci flips the same bits in Pi
    -------------------------------------------------- */

    size_t pos = plaintext.find("user");

    ciphertext[pos]     ^= ('u' ^ 'r');
    ciphertext[pos + 1] ^= ('s' ^ 'o');
    ciphertext[pos + 2] ^= ('e' ^ 'o');
    ciphertext[pos + 3] ^= ('r' ^ 't');

    /* manual decrypt without padding removal */

    auto blocks = split_blocks(ciphertext);

    std::vector<std::vector<uint8_t>> decrypted_blocks;
    std::vector<uint8_t> feedback = iv;

    for (const auto& block : blocks)
    {
        feedback = aes_encrypt_block(feedback, key);
        auto plain = xor_blocks(block, feedback);

        decrypted_blocks.push_back(plain);
    }

    auto merged = merge_blocks(decrypted_blocks);

    std::string result(merged.begin(), merged.end());

    std::cout << "\nPlaintext after attack:\n";
    std::cout << result.substr(0, plaintext.size()) << "\n";
}


/* ======================
   OFB Mode Interface
   ====================== */

void ofb_mode()
{
    int op;

    std::cout << "\nOFB Mode\n";
    std::cout << "1. Encrypt\n";
    std::cout << "2. Decrypt\n";
    std::cout << "3. Show Keystream Reuse Demo\n";
    std::cout << "4. Show Bit-Flipping Attack Demo\n";

    std::cin >> op;

    if (op == 3)
    {
        ofb_keystream_demo();
        return;
    }

    if (op == 4)
    {
        ofb_bitflip_demo();
        return;
    }

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