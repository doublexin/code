#ifndef yxyDESH
#define yxyDESH

#include <string.h>

        void Init(); 
        void InitializeKey(char* srcBytes,unsigned int keyN);
        void EncryptData(char* _srcBytes,unsigned int keyN);
        void DecryptData(char* _srcBytes,unsigned int keyN);
        void EncryptAnyLength(char* _srcBytes,unsigned int _bytesLength,unsigned int keyN);
        void DecryptAnyLength(char* _srcBytes,unsigned int _bytesLength, unsigned int keyN);
		void Bytes2Bits(char *srcBytes, char* dstBits, unsigned int sizeBits);
		void Bits2Bytes(char *dstBytes, char* srcBits, unsigned int sizeBits);
		void Int2Bits(unsigned int srcByte, char* dstBits);
		void Bits2Hex(char *dstHex, char* srcBits, unsigned int sizeBits);
		void Hex2Bits(char *srcHex, char* dstBits, unsigned int sizeBits);
        char* GetCiphertextInBinary();
		char* GetCiphertextInHex();
		char* GetCiphertextInBytes();
        char* GetPlaintext();
		char* GetCiphertextAnyLength();
        char* GetPlaintextAnyLength();
        void CreateSubKey(char* sz_56key,unsigned int keyN);
        void FunctionF(char* sz_Li,char* sz_Ri,unsigned int iKey,unsigned int keyN);
        void InitialPermuteData(char* _src,char* _dst);
        void ExpansionR(char* _src,char* _dst);
        void XOR(char* szParam1,char* szParam2, unsigned int uiParamLength, char* szReturnValueBuffer);
        void CompressFuncS(char* _src48, char* _dst32);
        void PermutationP(char* _src,char* _dst);
        void DecryptAnyLengthEx(char* _srcBytes, unsigned int keyN);
        unsigned char *b64_decode (const char *src);
        unsigned char *b64_decode_ex (const char *src, int len, int *decsize);

#endif
 