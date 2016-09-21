/*  CryptxHeader.cpp
 * - Header class for Cryptx RAP File
 *
 * June 2008
 * @author : Midhun Harikumar
 * (c) Centrum inc Software Solutions
 *
 * $ Version 0.4.5
 **/

# include <string>

# define RAP_FILE_ID "RAP5v06\0"

# if !defined(__CRYPTX_HEADER)
# define __CRYPTX_HEADER

 /*
   RapFileIdentifier		-	to id a proper rap file, with revision version
	OriginalExtention		-	original extension of file
	CryptxSignature		-	to test the decryption without converting the payload
	PayloadLength			-	length of data / payload only
	PayloadCRC32			-	checksum of payload file
 */

 class RapFileHeader
 {
private:
	char _rapFileIdentifier[8];			//  8 bytes
   char _originalExtension[8];      	//  8 bytes
   unsigned char _cryptxSignature[18]; // 18 bytes
   unsigned long _payloadSize;      	//  4 bytes
   unsigned long _payloadCRC32;     	//  4 bytes
					            		   	// --------
                                    	// 42 bytes

public:
	RapFileHeader() {	// 0-arg constructor
   	 _payloadSize  = 0L;
	    _payloadCRC32 = 0L;
   }

	RapFileHeader(char *sOrigExt,unsigned char signature[],unsigned long size,unsigned long crc){
      _payloadSize  = size;
      _payloadCRC32 = crc;
    	strcpy(_rapFileIdentifier,RAP_FILE_ID);
      strcpy(_cryptxSignature,signature);
   	strcpy(_originalExtension,sOrigExt);
   }

   char* getRapFileIdentifier(){		return _rapFileIdentifier;}
   char* getOriginalExtension(){ 	return _originalExtension;}
   unsigned char* getCryptxSignature(){return _cryptxSignature;}
	unsigned long getPayloadSize(){ 	return _payloadSize;}
   unsigned long getPayloadCRC(){	return _payloadCRC32;}

	// Diagnostic Purpose Function
   void printContents(void) const{
   	cout<<"ri ......... : "<<_rapFileIdentifier	<<endl;
   	cout<<"oe ......... : "<<_originalExtension	<<endl;
   	cout<<"cs ......... : "<<_cryptxSignature		<<endl;
   	cout<<"ps ......... : "<<_payloadSize			<<endl;
   	cout<<"pc ......... : "<<hex<<_payloadCRC32<<dec<<endl;
   }

   void printSizes(void) const{
   	cout<<"ri ......... : "<<sizeof(_rapFileIdentifier)<<endl;
   	cout<<"oe ......... : "<<sizeof(_originalExtension)<<endl;
   	cout<<"cs ......... : "<<sizeof(_cryptxSignature)	<<endl;
   	cout<<"ps ......... : "<<sizeof(_payloadSize)		<<endl;
   	cout<<"pc ......... : "<<sizeof(_payloadCRC32)		<<endl;
   }
};

# endif
