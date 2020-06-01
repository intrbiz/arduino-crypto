#include <ACrypto.h>             // AES 128 CBC with pkcs7, RNG, SHA256 and SHA256HMAC  
#include <base64.hpp>           // Base64 encode and decode without line breaks https://github.com/Densaugeo/base64_arduino

/*
 * AES encryption with SHA256HMAC on an ESP8266
 */

#define HMAC_KEY_LENGTH 16
#define AES_KEY_LENGTH 16

uint8_t* keyEncrypt;
uint8_t* keyHmac;
uint8_t keyHash[SHA256_SIZE];
uint8_t key[AES_KEY_LENGTH] = { 0x1C,0x3E,0x4B,0xAF,0x13,0x4A,0x89,0xC3,0xF3,0x87,0x4F,0xBC,0xD7,0xF3, 0x31, 0x31 };
uint8_t iv[AES_KEY_LENGTH];

SHA256 sha256;

// prints given block of given length in HEX
void printBlock(uint8_t* block, int length) {
  Serial.print(" { ");
  for (int i=0; i<length; i++) {
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
  // get SHA-256 hash of our secret key to create 256 bits of "key material"
  sha256.doUpdate(key, AES_KEY_LENGTH); 
  sha256.doFinal(keyHash);

  // keyEncrypt is a pointer pointing to the first 128 bits bits of "key material" stored in keyHash
  // keyHmac is a pointer poinging to the second 128 bits of "key material" stored in keyHashMAC
  keyEncrypt = keyHash;
  keyHmac = keyHash + AES_KEY_LENGTH;

  // maximum packet length for this example is 350 bytes. A crash occurs on larger packets.
  char packet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890\nabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890\nabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890\nabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890\nabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890\nabcdefghijklmnopqrstuvwxyzABCDEFGHI";
  // char packet[] = "1234567890 abcdefghijklmnopqrstuvwxyz !@#$%^&*()_+{|\\:\"<>?-=[];'./,"; 
  // char packet[] = "0123456789abcdef";

  Serial.println("On the sending side:");

  int packetSize = strlen(packet);
  Serial.printf("Packet (%d bytes):\n", packetSize);
  Serial.println(packet);
  
  Serial.print("Packet HEX");
  printBlock((uint8_t*)packet, packetSize+1);  //+1 to add null termination

  // random initialization vector
  RNG::fill(iv, AES_KEY_LENGTH);

  Serial.printf("Random IV (%d bytes)", AES_KEY_LENGTH);
  printBlock(iv, AES_KEY_LENGTH);

  AES aes(keyEncrypt, iv, AES::AES_MODE_128, AES::CIPHER_ENCRYPT);

  // create buffer for final message which will contain IV, encrypted message, and HMAC
  int encryptedSize = aes.calcSizeAndPad(packetSize);
  int ivEncryptedSize = encryptedSize + AES_KEY_LENGTH;
  int ivEncryptedHmacSize = ivEncryptedSize + SHA256HMAC_SIZE;
  uint8_t ivEncryptedHmac[ivEncryptedHmacSize];

  // copy IV to our final message buffer
  memcpy(ivEncryptedHmac, iv, AES_KEY_LENGTH);

  // encrypted is a pointer that points to the encypted messages position in our final message buffer
  uint8_t* encrypted = ivEncryptedHmac + AES_KEY_LENGTH;

  // AES 128 CBC and pkcs7 padding
  aes.process((uint8_t*)packet, encrypted, packetSize);

  Serial.printf("Encrypted (%d bytes)", encryptedSize);
  printBlock(encrypted, encryptedSize);

  // computedHmac is a pointer which points to the HMAC position in our final message buffer
  uint8_t* computedHmac = encrypted + encryptedSize;

  // compute HMAC/SHA-256 with keyHmac
  SHA256HMAC hmac(keyHmac, HMAC_KEY_LENGTH);
  hmac.doUpdate(ivEncryptedHmac, ivEncryptedSize);
  hmac.doFinal(computedHmac);

  Serial.printf("Computed HMAC (%d bytes)", SHA256HMAC_SIZE);
  printBlock(computedHmac, SHA256HMAC_SIZE);

  Serial.printf("IV | encrypted | HMAC (%d bytes)", ivEncryptedHmacSize);
  printBlock(ivEncryptedHmac, ivEncryptedHmacSize);
  
  // base64 encode
  int encodedSize = encode_base64_length(ivEncryptedHmacSize); // get size needed for base64 encoded output
  uint8_t encoded[encodedSize];
  encode_base64(ivEncryptedHmac, ivEncryptedHmacSize, encoded);

  Serial.printf("Base64 encoded to %d bytes\n", encodedSize);

  // Now on to the receiving side. This would normally be in a different skectch so we would
  // again SHA256 hash our secret key to obain keyEncrypt and KeyHmac on the remote side. 
  // We would then recompute the HMAC using the received iv plus encrypted mesage and 
  // compare the computed HMAC to the received HMAC. If they match, we can decrypt the message.

  Serial.printf("\nOn the receiving side:\n");
  
  // base64 decode
  int decodedSize = decode_base64_length(encoded);
  uint8_t decoded[decodedSize];
  decode_base64(encoded, decoded);

  Serial.printf("Received %d bytes\n", encodedSize);
  Serial.printf("Base64 decoded IV | encrypted | HMAC (%d bytes)", decodedSize);
  printBlock(decoded, decodedSize);
 
  // receivedHmac is a pointer which points to the received HMAC in our decoded message
  uint8_t* receivedHmac = decoded+decodedSize-SHA256HMAC_SIZE;

  Serial.printf("Received HMAC (%d bytes)", SHA256HMAC_SIZE);
  printBlock(receivedHmac, SHA256HMAC_SIZE); 

  // compute HMAC/SHA-256 with keyHmac
  uint8_t remote_computedHmac[SHA256HMAC_SIZE];  
  SHA256HMAC remote_hmac(keyHmac, HMAC_KEY_LENGTH);
  remote_hmac.doUpdate(decoded, decodedSize-SHA256HMAC_SIZE);
  remote_hmac.doFinal(remote_computedHmac);

  Serial.printf("Computed HMAC (%d bytes)", SHA256HMAC_SIZE);
  printBlock(remote_computedHmac, SHA256HMAC_SIZE);

  if (*receivedHmac == *remote_computedHmac) {
    // extract IV
    memcpy(iv, decoded, AES_KEY_LENGTH);

    Serial.printf("Received IV (%d bytes)", AES_KEY_LENGTH);
    printBlock(iv, AES_KEY_LENGTH);
  
    // decrypt 
    int decryptedSize = decodedSize - AES_KEY_LENGTH - SHA256HMAC_SIZE;
    char decrypted[decryptedSize];
    AES aesDecryptor(keyEncrypt, iv, AES::AES_MODE_128, AES::CIPHER_DECRYPT);
    aesDecryptor.process((uint8_t*)decoded + AES_KEY_LENGTH, (uint8_t*)decrypted, decryptedSize);  
    
    Serial.printf("Decrypted Packet HEX (%d bytes)", decryptedSize);
    printBlock((uint8_t*)decrypted, decryptedSize);
  
    Serial.printf("Decrypted Packet (%d bytes):\n", strlen(decrypted));
    Serial.println(decrypted);
  }
}

void loop() {
  delay(1);
}
