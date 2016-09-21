/* SideLiner.h 
 * - Constants and definitions
 *
 * July 2008
 * @author : Midhun Harikumar
 * (c) Centrum inc Software Solutions
 *
 * $ Version 0.1
 **/

//----------------------------------------------------

const char  g_applicationVersion[]   = "0.5_p0.7.8";
const char  g_applicationSignature[] = "SideLiner_CryptX";
const unsigned short g_keySize	     = 128;


//----------------------------------------------------
// STRING <-> HEX CONVERSION FUNCTIONS

//Function to convert unsigned char to string of length 2
void Char2Hex(unsigned char ch,unsigned char* szHex)
{
	unsigned char byte[2];
	byte[0] = ch/16;
	byte[1] = ch%16;
	for(int i=0; i<2; i++)
	{
		if(byte[i] >= 0 && byte[i] <= 9)
			szHex[i] = '0' + byte[i];
		else
			szHex[i] = 'A' + byte[i] - 10;
	}
	szHex[2] = 0;
}

//Function to convert string of length 2 to unsigned char
void Hex2Char(unsigned char const* szHex, unsigned char& rch)
{
	rch = 0;
	for(int i=0; i<2; i++)
	{
		if(*(szHex + i) >='0' && *(szHex + i) <= '9')
			rch = (rch << 4) + (*(szHex + i) - '0');
		else if(*(szHex + i) >='A' && *(szHex + i) <= 'F')
			rch = (rch << 4) + (*(szHex + i) - 'A' + 10);
		else
			break;
	}
}

//Function to convert string of unsigned chars to string of chars
void CharStr2HexStr(unsigned char const* pucCharStr, unsigned char* pszHexStr, int iSize)
{
	int i;
	unsigned char szHex[3];
	pszHexStr[0] = 0;
	for(i=0; i<iSize; i++)
	{
		Char2Hex(pucCharStr[i], szHex);
		strcat(pszHexStr, szHex);
	}
}

//Function to convert string of chars to string of unsigned chars
void HexStr2CharStr(unsigned char const* pszHexStr, unsigned char* pucCharStr, int iSize)
{
	int i;
	unsigned char ch;
	for(i=0; i<iSize; i++)
	{
		Hex2Char(pszHexStr+2*i, ch);
		pucCharStr[i] = ch;
	}
}

// end conv code
