#ifndef STOCKHOLM_H
#define STOCKHOLM_H

typedef struct stockholm_s {
	unsigned char key[32];
	unsigned char iv[16];
} stockholm_t;

#endif
