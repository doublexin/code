// des1.h: interface for the des class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_DES1_H__BE4828B5_8DBE_480D_AC3E_AF6410DE5FD5__INCLUDED_)
#define AFX_DES1_H__BE4828B5_8DBE_480D_AC3E_AF6410DE5FD5__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include <string.h>

class Des  
{
public:
	Des();
	virtual ~Des();
    void Init(); 
    void InitializeKey(char* srcBytes,unsigned int keyN);
    void EncryptData(char* _srcBytes,unsigned int keyN);
    void DecryptData(char* _srcBytes,unsigned int keyN);
    void EncryptAnyLength(char* _srcBytes,unsigned int _bytesLength,unsigned int keyN);
    void DecryptAnyLength(char* _srcBytes,unsigned int _bytesLength, unsigned int keyN);

    char* GetCiphertextInBinary();
	char* GetCiphertextInHex();
	char* GetCiphertextInBytes();
    char* GetPlaintext();
	char* GetCiphertextAnyLength();
    char* GetPlaintextAnyLength();

    void CreateSubKey(char* sz_56key,unsigned int keyN);
    void InitialPermuteData(char* _src,char* _dst);
    void DecryptAnyLengthEx(char* _srcBytes, unsigned int keyN);
    unsigned char *b64_decode (const char *src);
    unsigned char *b64_decode_ex (const char *src, int len, int *decsize);

protected:
	void Bytes2Bits(char *srcBytes, char* dstBits, unsigned int sizeBits);
	void Bits2Bytes(char *dstBytes, char* srcBits, unsigned int sizeBits);
	void Int2Bits(unsigned int srcByte, char* dstBits);
	void Bits2Hex(char *dstHex, char* srcBits, unsigned int sizeBits);
	void Hex2Bits(char *srcHex, char* dstBits, unsigned int sizeBits);
	void FunctionF(char* sz_Li,char* sz_Ri,unsigned int iKey,unsigned int keyN);
	void PermutationP(char* _src,char* _dst);
    void ExpansionR(char* _src,char* _dst);
    void XOR(char* szParam1,char* szParam2, unsigned int uiParamLength, char* szReturnValueBuffer);
    void CompressFuncS(char* _src48, char* _dst32);

private:
	char szSubKeys[2][16][48];
	char szCiphertextRaw[64];
	char szPlaintextRaw[64];
	char szCiphertextInBytes[8];
	char szPlaintextInBytes[8];

	char szCiphertextInBinary[65];
	char szCiphertextInHex[17];
	char szPlaintext[9];

	char szFCiphertextAnyLength[8192];
	char szFPlaintextAnyLength[8192];
};

#endif // !defined(AFX_DES1_H__BE4828B5_8DBE_480D_AC3E_AF6410DE5FD5__INCLUDED_)
