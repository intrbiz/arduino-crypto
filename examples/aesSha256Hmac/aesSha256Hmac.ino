#include <Crypto.h>             // AES 128 CBC with pkcs7, RNG, SHA256 and SHA256HMAC  
#include <base64.hpp>           // Base64 encode and decode without line breaks https://github.com/Densaugeo/base64_arduino

#define HMAC_KEY_LENGTH 16 

uint8_t keyEncrypt[AES_BLOCKSIZE];
uint8_t keyHmac[AES_BLOCKSIZE];
uint8_t keyHash[SHA256_SIZE];
uint8_t key[AES_BLOCKSIZE] = { 0x1C,0x3E,0x4B,0xAF,0x13,0x4A,0x89,0xC3,0xF3,0x87,0x4F,0xBC,0xD7,0xF3, 0x31, 0x31 };
uint8_t iv[AES_BLOCKSIZE];

SHA256 sha256;

// prints given block of given length in HEX
void printBlock(uint8_t* block, uint8_t length) {
  Serial.print(" { ");
  for (uint8_t i=0; i<length; i++) {
    Serial.print(block[i], HEX);
    Serial.print(" ");
  }
  Serial.println("}");
}

void setup() {
  Serial.begin(115200);
  while (!Serial) {
    ; //wait
  }

  Serial.printf("\n\n");

  // get SHA-256 hash of our secret key to create 256 bits of key material
  sha256.doUpdate(key, AES_BLOCKSIZE); 
  sha256.doFinal(keyHash);

  // separate 256 bit key material into two 128 bit keys. one for encryption and one for MAC
  memcpy(keyEncrypt, keyHash, AES_BLOCKSIZE);
  memcpy(keyHmac, keyHash+AES_BLOCKSIZE, AES_BLOCKSIZE);
}

void loop() {
  char packet[] = "1234567890 abcdefghijklmnopqrstuvwxyz !@#$%^&*()_+{|\\:\"<>?-=[];'./,"; 
//  char packet[] = "0123456789abcdef";

  Serial.println("On the sending side:");
  
  Serial.print("Packet: ");
  Serial.println(packet);
  uint8_t packetSize = strlen(packet);
  
  Serial.print("Packet HEX");
  printBlock((uint8_t*)packet, packetSize+1);  //+1 to add null termination

  // random initialization vector
  RNG::fill(iv, AES_BLOCKSIZE);

  Serial.print("Random IV");
  printBlock(iv, AES_BLOCKSIZE);

  AES aes(keyEncrypt, iv, AES::AES_MODE_128, AES::CIPHER_ENCRYPT);

  // create buffer for encrypted message with size that is a multiple of AES block size
  uint8_t encryptedSize = aes.calc_buffer_size(packet);
  uint8_t encrypted[encryptedSize];

  // create buffer for final message which will contain IV, encrypted message, and HMAC 
  uint8_t ivEncryptedSize = encryptedSize + AES_BLOCKSIZE;
  uint8_t ivEncryptedHmacSize = ivEncryptedSize + SHA256HMAC_SIZE;
  uint8_t ivEncryptedHmac[ivEncryptedHmacSize];

  // copy IV to our final message buffer
  memcpy(ivEncryptedHmac, iv, AES_BLOCKSIZE);

  // AES 128 CBC and pkcs7 padding
  aes.process((uint8_t*)packet, encrypted, packetSize);

  // append encrypted to our final message buffer
  memcpy(ivEncryptedHmac+AES_BLOCKSIZE, encrypted, encryptedSize);

  Serial.print("Encrypted");
  printBlock(encrypted, encryptedSize);

  // compute HMAC/SHA-256 with keyHmac
  SHA256HMAC hmac(keyHmac, HMAC_KEY_LENGTH);
  hmac.doUpdate(ivEncryptedHmac, ivEncryptedSize);

  uint8_t computedHmac[SHA256HMAC_SIZE];
  hmac.doFinal(computedHmac);

  Serial.print("Computed HMAC");
  printBlock(computedHmac, SHA256HMAC_SIZE);

  // append HMAC to our final message
  memcpy(ivEncryptedHmac+AES_BLOCKSIZE+encryptedSize, computedHmac, SHA256HMAC_SIZE);

  Serial.print("IV | encrypted | HMAC");
  printBlock(ivEncryptedHmac, ivEncryptedHmacSize);
  
  // base64 encode
  uint8_t encodedSize = encode_base64_length(ivEncryptedHmacSize); // get size needed for base64 encoded output
  uint8_t encoded[encodedSize];
  encode_base64(ivEncryptedHmac, ivEncryptedHmacSize, encoded);

  Serial.print("Encoded: ");
  Serial.println((char*)encoded);

  // Now on to the receiving side. This would normally be in a different skectch so we would
  // again SHA256 hash our secret key to obain keyEncrypt and KeyHmac on the remote side. 
  // We would then recompute the HMAC using the received iv plus encrypted mesage and 
  // compare the computed HMAC to the extraced HMAC. if they match, we can decrypt the message.

  Serial.printf("\nOn the receiving side:\n");
  
  // base64 decode
  uint8_t decodedSize = decode_base64_length(encoded);
  uint8_t decoded[decodedSize];
  decode_base64(encoded, decoded);

  Serial.print("Decoded HEX");
  printBlock(decoded, decodedSize);

  // extract HMAC
  uint8_t extractedHmac[SHA256HMAC_SIZE];
  memcpy(extractedHmac, decoded+decodedSize-SHA256HMAC_SIZE, SHA256HMAC_SIZE);

  Serial.print("Received HMAC");
  printBlock(extractedHmac, SHA256HMAC_SIZE); 

  // compute HMAC/SHA-256 with keyHmac
  SHA256HMAC remote_hmac(keyHmac, HMAC_KEY_LENGTH);
  remote_hmac.doUpdate(decoded, decodedSize-SHA256HMAC_SIZE);

  uint8_t remote_computedHmac[SHA256HMAC_SIZE];
  remote_hmac.doFinal(remote_computedHmac);

  Serial.print("Computed HMAC");
  printBlock(remote_computedHmac, SHA256HMAC_SIZE);

  if (*extractedHmac == *remote_computedHmac) {
    // extract IV
    memcpy(iv, decoded, AES_BLOCKSIZE);

    Serial.print("Received IV");
    printBlock(iv, AES_BLOCKSIZE);
  
    // decrypt 
    uint8_t decryptedSize = decodedSize - AES_BLOCKSIZE - SHA256HMAC_SIZE;
    uint8_t decrypted[decryptedSize];
    AES aesDecryptor(keyEncrypt, iv, AES::AES_MODE_128, AES::CIPHER_DECRYPT);
    aesDecryptor.process((uint8_t*)decoded + AES_BLOCKSIZE, decrypted, decryptedSize);  
  
    Serial.print("Decrypted: ");
    Serial.println((char*)decrypted);
  
    Serial.print("Decrypted HEX");
    printBlock(decrypted, decryptedSize);
  }

  Serial.println("");

  ESP.deepSleep(0);
}
