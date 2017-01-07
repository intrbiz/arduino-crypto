#include <Crypto.h>

/*
 * Compute the SHA256 hash of a message on an ESP8266
 */

void setup()
{
  // Setup Serial
  Serial.begin(9600);
  Serial.println("SHA256 example");
  
  /* Create a SHA256 hash */
  SHA256 hasher;
  
  /* Update the hash with your message, as many times as you like */
  const char *hello = "Hello World";
  hasher.doUpdate(hello, strlen(hello));
  
  /* Update the hash with just a plain string*/
  hasher.doUpdate("Goodbye World");
  
  /* Update the hash with a binary message */
  byte message[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
  hasher.doUpdate(message, sizeof(message));
  
  /* Compute the final hash */
  byte hash[SHA256_SIZE];
  hasher.doFinal(hash);
  
  /* hash now contains our 32 byte hash */
  for (byte i; i < SHA256_SIZE; i++)
  {
      Serial.print(hash[i], HEX);
  }
}


void loop()
{
  
}
