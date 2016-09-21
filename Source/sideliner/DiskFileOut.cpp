/*  DiskFileOut.cpp
 * - Inherits a basic DiskFile for Writing purpose
 *
 * June 2008
 * @author : Midhun Harikumar
 * (c) Centrum inc Software Solutions
 *
 * $ Version 0.3.2 / p 0.1
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

namespace DiskFileOutBlock
{
	//////////////////////
	//
   class DiskFileOut : public DiskFileBlock :: DiskFile
   {
private:
      bool isFileOpen;
		ofstream outHandle;
      RapFileHeader header;

public:
		DiskFileOut() : DiskFileBlock :: DiskFile(){
          isFileOpen = false;
      }
      DiskFileOut(char *sFilePath): DiskFileBlock :: DiskFile(sFilePath) {
      	outHandle.open(sFilePath,ios::binary);
         if(outHandle)
         	isFileOpen = true;
      }

		void reopenFile();
      void closeFile();
      void writeBlock(RapFileHeader h);
      void writeBlock(Block b);
      void writeBlock(char *block);
      void writeBlock(unsigned char *block, unsigned int length);
      unsigned long getFileCRC();
	};
   //
   /////////////////////

   unsigned long DiskFileOut :: getFileCRC(){
   		DiskFileBlock :: DiskFile :: calcFileCRC();
			return DiskFile :: getFileCRC32();
   }

   void DiskFileOut :: reopenFile(){			// Reopen a closed file
	   if(isFileOpen == false){
      	outHandle.open(getFilePath(),ios::binary);
         if(outHandle)
         	isFileOpen = true;
      }
   }
   void DiskFileOut :: closeFile(){				// Close an open file
	   if(isFileOpen == true){
	   	outHandle.close();
   	   isFileOpen = false;
      }
   }

	void DiskFileOut :: writeBlock(RapFileHeader h){
   	if(isFileOpen){
         outHandle.write(reinterpret_cast<char*>(&h),sizeof(h));
         return;
      }
      else{ /*Could not open file*/      }
   }

	void DiskFileOut :: writeBlock(char *block){
   	if(isFileOpen){
         outHandle.write(block,strlen(block));
         return;
      }
      else{ /*Could not open file*/      }
   }
   void DiskFileOut :: writeBlock(unsigned char *block,unsigned int length){
   	if(isFileOpen){
         outHandle.write(block,length);
         return;
      }
      else{ /*Could not open file*/      }
   }

   void DiskFileOut :: writeBlock(Block b){
   	if(isFileOpen){
         outHandle.write(reinterpret_cast<char*>(&b),sizeof(b));
         return;
      }
      else{
       	;	// Could not open file
      }
   }

}
