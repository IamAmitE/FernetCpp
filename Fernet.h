#pragma once
#ifndef _FERNET_CPP_H
#define _FERNET_CPP_H

#include <string>
#include <vector>
#include <exception>
#include <cryptopp/osrng.h>
#include <cryptopp/modes.h>

namespace Fernet {

    const char base64_url_alphabet[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
    };


    std::string base64_encode(const std::string& in) {
        std::string out;
        int val = 0, valb = -6;
        size_t len = in.length();
        unsigned int i = 0;
        for (i = 0; i < len; i++) {
            unsigned char c = in[i];
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                out.push_back(base64_url_alphabet[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6) {
            out.push_back(base64_url_alphabet[((val << 8) >> (valb + 8)) & 0x3F]);
        }
        switch (out.size() % 4) {
        case 2:
            out = out + std::string("==");
            break;
        case 3:
            out = out + std::string("=");
            break;
        default:
            break;
        }
        return out;
    }


    std::string base64_decode(const std::string& in) {
        std::string out;
        std::vector<int> T(256, -1);
        unsigned int i;
        for (i = 0; i < 64; i++) T[base64_url_alphabet[i]] = i;

        int val = 0, valb = -8;
        for (i = 0; i < in.length(); i++) {
            unsigned char c = in[i];
            if (T[c] == -1) break;
            val = (val << 6) + T[c];
            valb += 6;
            if (valb >= 0) {
                out.push_back(char((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        return out;
    }


    std::string long_long_to_big_endian(unsigned long long num) {
        std::vector<unsigned char> bigEndian;
        for (int i = 7; i >= 0; i--) {
            bigEndian.push_back((num >> (8 * i)) & 0xff);
        }
        return std::string(bigEndian.begin(), bigEndian.end());

    }

    std::string fernet_encrypt(std::string data, std::string key) {
        CryptoPP::AutoSeededRandomPool rnd;
        std::string decoded_key = base64_decode(key);
        if (decoded_key.length() != 32) {
            throw std::invalid_argument("Fernet encryption key must be 32 bytes.");
        }
        std::string signing_key = decoded_key.substr(0, 16);
        std::string aes_key = decoded_key.substr(16, 16);
        auto iv = CryptoPP::SecByteBlock(0x00, 16);
        rnd.GenerateBlock(iv, 16);
        std::chrono::seconds ms = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch());
        unsigned long long time = ms.count();

        CryptoPP::byte signing_key_bytes[16], aes_key_bytes[16];
        for (int i = 0; i < 16; i++) {
            signing_key_bytes[i] = CryptoPP::byte(signing_key[i]);
            aes_key_bytes[i] = CryptoPP::byte(aes_key[i]);
        }

        // Perform AES encryption

        std::string aes_encrypted;

        CryptoPP::AES::Encryption aesEncryption(aes_key_bytes, CryptoPP::AES::DEFAULT_KEYLENGTH);
        CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

        CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(aes_encrypted));
        stfEncryptor.Put(reinterpret_cast<const unsigned char*>(data.c_str()), data.length());
        stfEncryptor.MessageEnd();

        // construct base parts string

        std::string base_parts = std::string("\x80" + long_long_to_big_endian(time) + std::string(reinterpret_cast<const char*>(iv.data()), iv.size()) + aes_encrypted);

        // generate HMAC

        auto base_parts_bytes = CryptoPP::SecByteBlock(0x00, base_parts.length());
        for (int i = 0; i < base_parts.length(); i++) {
            base_parts_bytes[i] = base_parts[i];
        }

        CryptoPP::HMAC<CryptoPP::SHA256> hmac(signing_key_bytes);
        hmac.Update(base_parts_bytes.data(), base_parts.size());

        CryptoPP::byte hmac_digest[CryptoPP::HMAC<CryptoPP::SHA256>::DIGESTSIZE];
        hmac.Final(hmac_digest);

        std::string hmac_digest_string(reinterpret_cast<const char*>(hmac_digest), sizeof(hmac_digest));

        return base64_encode(base_parts + hmac_digest_string);

    }
}


#endif