/**
 * An extremely minimal crypto library for Arduino devices.
 * 
 * The SHA256 and AES implementations are derived from axTLS 
 * (http://axtls.sourceforge.net/), Copyright (c) 2008, Cameron Rich.
 * 
 * Ported and refactored by Chris Ellis 2016.
 * pkcs7 padding routines added by Mike Killewald Nov 26, 2017 (adopted from https://github.com/spaniakos/AES).
 *
 */

#ifndef CRYPTO_h
#define CRYPTO_h

#include <Arduino.h>
#include <osapi.h>

#define SHA256_SIZE             32
#define SHA256HMAC_SIZE         32
#define SHA256HMAC_BLOCKSIZE    64
#define AES_MAXROUNDS           14
#define AES_BLOCKSIZE           16
#define AES_IV_SIZE             16
#define AES_IV_LENGTH           16
#define AES_128_KEY_LENGTH      16
#define AES_256_KEY_LENGTH      16

/**
 * Compute a SHA256 hash
 */
class SHA256
{
    public:
        SHA256();
        /**
         * Update the hash with new data
         */
        void doUpdate(const byte *msg, int len);
        void doUpdate(const char *msg, unsigned int len) { doUpdate((byte*) msg, len); }
        void doUpdate(const char *msg) { doUpdate((byte*) msg, strlen(msg)); }
        /**
         * Compute the final hash and store it in [digest], digest must be 
         * at least 32 bytes
         */
        void doFinal(byte *digest);
        /**
         * Compute the final hash and check it matches this given expected hash
         */
        bool matches(const byte *expected);
    private:
        void SHA256_Process(const byte digest[64]);
        uint32_t total[2];
        uint32_t state[8];
        uint8_t  buffer[64];
};

#define HMAC_OPAD 0x5C
#define HMAC_IPAD 0x36

/**
 * Compute a HMAC using SHA256
 */
class SHA256HMAC
{
    public:
        /**
         * Compute a SHA256 HMAC with the given [key] key of [length] bytes 
         * for authenticity
         */
        SHA256HMAC(const byte *key, unsigned int keyLen);
        /**
         * Update the hash with new data
         */
        void doUpdate(const byte *msg, unsigned int len);
        void doUpdate(const char *msg, unsigned int len) { doUpdate((byte*) msg, len); }
        void doUpdate(const char *msg) { doUpdate((byte*) msg, strlen(msg)); }
        /**
         * Compute the final hash and store it in [digest], digest must be 
         * at least 32 bytes
         */
        void doFinal(byte *digest);
        /**
         * Compute the final hash and check it matches this given expected hash
         */
        bool matches(const byte *expected);
    private:
        void blockXor(const byte *in, byte *out, byte val, byte len);
        SHA256 _hash;
        byte _innerKey[SHA256HMAC_BLOCKSIZE];
        byte _outerKey[SHA256HMAC_BLOCKSIZE];
};

/**
 * AES 128 and 256, based on code from axTLS
 */
 class AES
{
    public:
        typedef enum
        {
            AES_MODE_128,
            AES_MODE_256
        } AES_MODE;
        typedef enum
        {
            CIPHER_ENCRYPT = 0x01,
            CIPHER_DECRYPT = 0x02
        } CIPHER_MODE;
        /**
         * Create this cipher instance in either encrypt or decrypt mode
         *
         * Use the given [key] which must be 16 bytes long for AES 128 and
         *  32 bytes for AES 256
         *
         * Use the given [iv] initialistion vection which must be 16 bytes long
         *
         * Use the either AES 128 or AES 256 as specified by [mode]
         *
         * Either encrypt or decrypt as specified by [cipherMode]
         */
        AES(const uint8_t *key, const uint8_t *iv, AES_MODE mode, CIPHER_MODE cipherMode);
        /**
         * Either encrypt or decrypt [in] and store into [out] for [length] bytes.
         *
         * Note: the length must be a multiple of 16 bytes
         */
        void process(const uint8_t *in, uint8_t *out, int length);
    
        /** Getter method for size
         *
         * This function returns the size
         * @return an integer, that is the size of the of the padded plaintext,
         * thus, the size of the ciphertext.
         */
        int get_size();
    
        /** Setter method for size
         *
         * This function sets the size of the plaintext+pad
         *
         */
        void set_size(int sizel);
    
        /** Calculates the size of the buffer needed to hold the cipher text.
         *
         * Calculates the size of the buffer needed to hold the cipher text
         *
         * @param text the plaintext character array
         * @return an integer that is the size of buffer needed to hold the cipher text.
         */
        int calc_buffer_size(char* text);
    
        /** Calculates the size of the plaintext and the padding.
         *
         * Calculates the size of the plaintext with the size of the
         * padding needed. Moreover it stores them in their class variables.
         *
         * @param in_size the size of the byte array ex sizeof(plaintext)
         */
        void calc_size_n_pad(int in_size);
    
        /** Pads the plaintext
         *
         * This function pads the plaintext and returns an char array with the
         * plaintext and the padding in order for the plaintext to be compatible with
         * 16bit size blocks required by AES
         *
         * @param in the string of the plaintext in a byte array
         * @param out The string of the out array.
         * @return no return, The padded plaintext is stored in the out pointer.
         */
        void padPlaintext(const uint8_t* in, uint8_t* out);
    
        /** Check the if the padding is correct.
         *
         * This functions checks the padding of the plaintext.
         *
         * @param in the string of the plaintext in a byte array
         * @param size the size of the string
         * @return true if correct / false if not
         */
        bool CheckPad(uint8_t* in, int lsize);
    
    private:
        void encryptCBC(const uint8_t *in, uint8_t *out, int length);
        void decryptCBC(const uint8_t *in, uint8_t *out, int length);
        void convertKey();
        void encrypt(uint32_t *data);
        void decrypt(uint32_t *data);
        uint16_t _rounds;
        uint16_t _key_size;
        uint32_t _ks[(AES_MAXROUNDS+1)*8];
        uint8_t _iv[AES_IV_SIZE];
        uint8_t _pad_size; // size of padding to add to plaintext
        uint8_t _size; // size of plaintext to be ciphered
        uint8_t _arr_pad[15];
        CIPHER_MODE _cipherMode;
};

/**
 * ESP8266 specific random number generator
 */
class RNG
{
    public:
        /**
         * Fill the [dst] array with [length] random bytes
         */
        static void fill(uint8_t *dst, unsigned int length);
        /**
         * Get a random byte
         */
        static byte get();
        /**
         * Get a 32bit random number
         */
        static uint32_t getLong();
    private:
};

#endif
