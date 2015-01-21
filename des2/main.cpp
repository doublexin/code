//#include "DES.h"
#include "des2.h"
#include <iostream>
using namespace std;


int main()
{
	DES2 des2;
	const unsigned char *str = (const unsigned char *)"10086" ;
	
	int len = sizeof(str) * 8;
	LPBYTE dstr = (unsigned char *)calloc(256, sizeof(dstr));
	LPBYTE dstr2 = (unsigned char *)calloc(256, sizeof(dstr));
	cout << sizeof(str) << endl;
	//CDesEnter(LPCBYTE in, LPBYTE out, int datalen, const BYTE key[8], BOOL type)

	const BYTE key[8] = {'U','E','6', 'C', 'h', 'V', 'r', '6'};
	bool type = 0;
	
	des2.CDesEnter(str, dstr, len, key, type);
	cout << " Cipher text \n" << dstr << endl;
	des2.CDesEnter(dstr, dstr2, len, key, 1);
	cout << " Plain  text \n" << dstr2 << endl;
	

}