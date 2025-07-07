// #include "AES.hpp"

/* For string */
#include <string>

/* For RAND_bytes() */
#include <openssl/rand.h>

#define AES_KEY_LEN 16
void Stockholm( void )
{
	const char *data = "secret data";
	unsigned char key[AES_KEY_LEN];

	RAND_bytes(key, sizeof(key));
}
