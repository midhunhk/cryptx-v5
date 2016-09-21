/*  Block.cpp
 * - Defines an encrypted block in Cryptx
 *
 * June 2008
 * @author : Midhun Harikumar
 * (c) Centrum inc Software Solutions
 *
 * $ Version 0.3.1
 **/

# include <string>

# if !defined(__BLOCK)
# define __BLOCK

class Block
{
	unsigned int  blockLength;
   unsigned char blockOfData[32];

public:

	Block() : blockLength(0L)
   	{ blockOfData[0] = '\0';}
   Block(unsigned char* data)
   	{
      	strcpy(blockOfData,data);
         blockLength = strlen(blockOfData);
      }
   Block(unsigned char* data,unsigned int alt)
   	{
      	strcpy(blockOfData,data);
         blockLength = strlen(blockOfData);
      }

   unsigned int   getBlockLength(){ return blockLength;}
   unsigned char* getBlockData()  { return blockOfData;}

};

# endif