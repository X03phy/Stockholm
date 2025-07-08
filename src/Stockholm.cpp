// #include "AES.hpp"

/* For RAND_bytes() */
#include <openssl/rand.h>

/* For perror() */
#include <stdio.h> 

/* For exit() */
#include <stdlib.h>

/* For AES-128 encryption */
#define AES_KEY_LEN 16
#define AES_ENCRYPTION_TYPE_LEN AES_KEY_LEN * 8

int encrypt( unsigned char *data, int data_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext )
{
	/* Length */
	int ciphertext_len = 0;
	int len = 0;

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	if ( !ctx ) // Probleme de malloc
	{
		perror( "EVP_CIPHER_CTX_new() failed" );
		exit( 1 );
	}

	if ( !EVP_EncryptInit_ex( ctx, EVP_aes_128_gcm(), NULL, key, iv ) )
	{
		EVP_CIPHER_CTX_free( ctx ); // free correctement ctx
		perror( "EVP_EncryptInit_ex() failed" );
		exit( 2 );
	}

	if ( !EVP_EncryptUpdate( ctx, ciphertext, &len, data, data_len ) )
	{
		EVP_CIPHER_CTX_free( ctx ); // free correctement ctx
		perror( "EVP_EncryptUpdate() failed" );
		exit( 3 );
	}

	ciphertext_len += len;

	if ( !EVP_EncryptFinal_ex( ctx, ciphertext + len, &len ) )
	{
		EVP_CIPHER_CTX_free( ctx ); // free correctement ctx
		perror( "EVP_EncryptFinal_ex() failed" );
		exit( 4 );
	}

	EVP_CIPHER_CTX_free( ctx ); // free correctement ctx

	return ( ciphertext_len );
}

int decrypt( unsigned char *ciphertext, int cipher_len, unsigned char *key, unsigned char *iv, unsigned char *text )
{
	int text_len = 0;
	int len = 0;

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	if ( !ctx ) // Probleme de malloc
	{
		perror( "EVP_CIPHER_CTX_new() failed" );
		exit( 5 );
	}

	if ( !EVP_DecryptInit_ex( ctx, EVP_aes_128_gcm(), NULL, key, iv ) )
}
