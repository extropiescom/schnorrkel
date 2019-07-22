#include <string.h>
#include <stdlib.h>
#include "libsr.h"
#include "sr_test.h"


unsigned int __sheap = 0x20000400;
unsigned char rv = 0;
unsigned char* u8 = 0;

void simple_test()
{
	unsigned char *p1 =  0;
	//unsigned char *p2 =  0;
	unsigned char mes[96] = { 0 };
	unsigned char mes2[96] = { 0 };
	memset(mes,0x56,96);
	memset(mes2,0x78,96);
	sr_init();
	p1 = test_box(mes);
	sr_free(p1);
	//p2 = test_box(mes2);
	//sr_free(p2);
	rv = test_sign_verify();
}

void api_test()
{
	unsigned char g_message[32] = { 0x32,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,};
	unsigned char g_random[32] = { 0 };
	unsigned char g_keypair[96] = { 74,83,195,251,188,89,151,14,229,248,90,248,19,135,93,255,193,58,144,74,46,83,174,126,101,250,13,234,110,98,201,1,159,7,231,190,85,81,56,122,152,186,151,124,115,45,8,13,203,15,41,160,72,227,101,105,18,198,83,62,50,238,122,237,156,102,163,57,200,52,79,146,47,195,32,108,181,218,232,20,165,148,192,23,125,211,35,92,37,77,156,64,154,101,184,8 }; 

	
	  sr_init();
		u8 = sr_sign(g_message,32,g_random,g_keypair);
}

void main(void)
{
	//simple_test();
	api_test();
	
	while(1)
	{

	}
}