/*  DiskFileIn.cpp 
 * - Inherits a basic DiskFile for Reading purpose 
 *
 * June 2008 
 * @author : Midhun Harikumar 
 * (c) Centrum inc Software Solutions 
 *
 * $ Version 0.3.1.1 / p 0.1
 * [] uses C++ code of calculating filesize 
 **/

// Includes

# include <stdio>
# include <string>
# include <fstream>
# include <iostream>

# include "Block.cpp"
# include "DiskFile.cpp"
# include "CryptxHeader.cpp"

/////////////////////////

using namespace std;

namespace DiskFileInBlock
{
	//////////////////////
	//
   class DiskFileIn : public DiskFileBlock :: DiskFile
   {
private:
      ifstream is;
		unsigned long fileSize;
      bool isFileOpen;
      Block objBlock;
      RapFileHeader header;
   	unsigned char buffer[512];
public:
		// Call Base class constructors as Well
		DiskFileIn() : DiskFileBlock :: DiskFile(){
      	isFileOpen = false;
         fileSize   = 0L;
      }
      DiskFileIn(char *sFilePath) : DiskFileBlock :: DiskFile(sFilePath) {

        	is.open(sFilePath,ios::binary);
         isFileOpen = (is.good())?true:false;
         if(isFileOpen)
         {
	        	// calculate FileSize
            is.seekg(0,ios::end);			// move 0 bytes from end
  		   	fileSize = is.tellg();			// get offset
   			is.seekg(0,ios::beg);			// rewind

	        	// calculate CRC
				DiskFileBlock :: DiskFile :: calcFileCRC();
         }
      }

      // Destructor
      ~DiskFileIn(){
      	if(isFileOpen)
         	is.close();
      }

      unsigned long  getFileSize();
      void				resetFP();
      bool           fileOpen();
		RapFileHeader  readHeader();
      Block				readABlock();
      unsigned char* readBlock();
      unsigned char* readBlock(unsigned int blockSize);
   };
   //
   /////////////////////

   bool DiskFileIn :: fileOpen(){ return isFileOpen;}
	unsigned long DiskFileIn :: getFileSize(){ return fileSize;}
   void DiskFileIn :: resetFP(){is.seekg(0,ios::beg);}

   Block DiskFileIn :: readABlock()
   {
   	if(isFileOpen){
         is.read(reinterpret_cast<char*>(&objBlock),sizeof(objBlock));
      }
      return objBlock;
   }

	RapFileHeader DiskFileIn :: readHeader()
   {
   	if(isFileOpen){
         is.read(reinterpret_cast<char*>(&header),sizeof(header));
      }
      return header;
   }

   unsigned char* DiskFileIn :: readBlock(unsigned int blockSize)
   {     /*
   		// Should check if file is open already!
         is.read(buffer,blockSize);
	      buffer[blockSize] = '\0';	// Forcefully put EOS, may be cause of bug in later stages
         */
         is.read(reinterpret_cast<char*>(&buffer),blockSize);
      return buffer;
   }

}
/*
if the input file is to be encrypted,
	calculate the crc and file size
   read block by block

if the input file is to be decrypted
	read the header
   read the payload block by block (payload size = file size - header size)
*/
