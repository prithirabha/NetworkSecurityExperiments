#include "ctr.hpp"

#include <iostream>
#include <string>
#include <limits>

#include "../crypto_utils.hpp"
#include "../aes/aes_wrapper.hpp"


/* ======================
   Counter Increment
   ====================== */

void increment_counter(std::vector<uint8_t>& counter)
{
    for (int i = AES_BLOCK_SIZE - 1; i >= 0; --i)
    {
        counter[i]++;

        if (counter[i] != 0)
            break;
    }
}


/* ======================
   CTR Encryption
   ====================== */

std::vector<uint8_t> ctr_encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce
)
{
    auto blocks = split_blocks(pkcs7_pad(plaintext));

    std::vector<std::vector<uint8_t>> encrypted_blocks;

    std::vector<uint8_t> counter = nonce;

    for (const auto& block : blocks)
    {
        auto keystream = aes_encrypt_block(counter, key);

        auto cipher = xor_blocks(block, keystream);

        encrypted_blocks.push_back(cipher);

        increment_counter(counter);
    }

    return merge_blocks(encrypted_blocks);
}


/* ======================
   CTR Decryption
   ====================== */

std::vector<uint8_t> ctr_decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce
)
{
    auto blocks = split_blocks(ciphertext);

    std::vector<std::vector<uint8_t>> decrypted_blocks;

    std::vector<uint8_t> counter = nonce;

    for (const auto& block : blocks)
    {
        auto keystream = aes_encrypt_block(counter, key);

        auto plain = xor_blocks(block, keystream);

        decrypted_blocks.push_back(plain);

        increment_counter(counter);
    }

    auto merged = merge_blocks(decrypted_blocks);

    return pkcs7_unpad(merged);
}

/* ===========================
   CTR Nonce Reuse Demo
   =========================== */

void ctr_nonce_reuse_demo()
{
    std::cout << "\n=== CTR Nonce Reuse Demo ===\n";

    std::string p1 = "attack at dawn!!!!";
    std::string p2 = "attack at dusk!!!!";

    std::string key_str   = "0123456789012345";
    std::string nonce_str = "1234567890123456";

    std::vector<uint8_t> key(key_str.begin(), key_str.end());
    std::vector<uint8_t> nonce(nonce_str.begin(), nonce_str.end());

    std::vector<uint8_t> data1(p1.begin(), p1.end());
    std::vector<uint8_t> data2(p2.begin(), p2.end());

    auto c1 = ctr_encrypt(data1, key, nonce);
    auto c2 = ctr_encrypt(data2, key, nonce);

    auto cx = xor_blocks(c1, c2);
    auto px = xor_blocks(data1, data2);

    std::cout << "\nPlaintext1:\n" << p1 << "\n";
    std::cout << "\nPlaintext2:\n" << p2 << "\n";

    std::cout << "\nC1 XOR C2:\n";
    std::cout << bytes_to_hex(cx) << "\n";

    std::cout << "\nP1 XOR P2:\n";
    std::cout << bytes_to_hex(px) << "\n";
}

/* ===========================
   CTR Bit-Flipping Attack Demo
   =========================== */

void ctr_bitflip_demo()
{
    std::cout << "\n=== CTR Bit-Flipping Attack Demo ===\n";

    std::string plaintext = "role=user;access=limited;";

    std::string key_str   = "0123456789012345";
    std::string nonce_str = "1234567890123456";

    std::vector<uint8_t> key(key_str.begin(), key_str.end());
    std::vector<uint8_t> nonce(nonce_str.begin(), nonce_str.end());

    std::vector<uint8_t> data(plaintext.begin(), plaintext.end());

    auto ciphertext = ctr_encrypt(data, key, nonce);

    std::cout << "\nOriginal plaintext:\n";
    std::cout << plaintext << "\n";

    /* --------------------------------------------------
       CTR malleability

       Pi = Ci XOR Oi

       Changing Ci flips bits in Pi
    -------------------------------------------------- */

    size_t pos = plaintext.find("user");

    ciphertext[pos]     ^= ('u' ^ 'r');
    ciphertext[pos + 1] ^= ('s' ^ 'o');
    ciphertext[pos + 2] ^= ('e' ^ 'o');
    ciphertext[pos + 3] ^= ('r' ^ 't');

    /* manual decryption (no padding removal) */

    auto blocks = split_blocks(ciphertext);

    std::vector<std::vector<uint8_t>> decrypted_blocks;
    std::vector<uint8_t> counter = nonce;

    for (const auto& block : blocks)
    {
        auto stream = aes_encrypt_block(counter, key);
        auto plain  = xor_blocks(block, stream);

        decrypted_blocks.push_back(plain);

        for (int i = AES_BLOCK_SIZE - 1; i >= 0; --i)
        {
            counter[i]++;
            if (counter[i] != 0) break;
        }
    }

    auto merged = merge_blocks(decrypted_blocks);

    std::string result(merged.begin(), merged.end());

    std::cout << "\nPlaintext after attack:\n";
    std::cout << result.substr(0, plaintext.size()) << "\n";
}

/* ======================
   CTR Mode Interface
   ====================== */

void ctr_mode()
{
    int op;

    std::cout << "\nCTR Mode\n";
    std::cout << "1. Encrypt\n";
    std::cout << "2. Decrypt\n";
    std::cout << "3. Show Nonce Reuse Demo\n";
    std::cout << "4. Show Bit-Flipping Attack Demo\n";

    std::cin >> op;

    if (op == 3)
    {
        ctr_nonce_reuse_demo();
        return;
    }

    if (op == 4)
    {
        ctr_bitflip_demo();
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

    std::string nonce_str;

    while (true)
    {
        std::cout << "Enter 16-byte nonce: ";
        std::cin >> nonce_str;

        if (nonce_str.size() == AES_BLOCK_SIZE)
            break;
    }

    std::vector<uint8_t> data;

    if (op == 1)
        data = std::vector<uint8_t>(input.begin(), input.end());
    else
        data = hex_to_bytes(input);

    std::vector<uint8_t> key(key_str.begin(), key_str.end());
    std::vector<uint8_t> nonce(nonce_str.begin(), nonce_str.end());

    std::vector<uint8_t> result;

    if (op == 1)
        result = ctr_encrypt(data, key, nonce);
    else
        result = ctr_decrypt(data, key, nonce);

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