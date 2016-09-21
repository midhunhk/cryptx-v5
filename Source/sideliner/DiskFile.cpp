/*  DiskFile.cpp
 * - Abstract Class that represents a DiskFile
 *
 * June 2008
 * @author : Midhun Harikumar
 * (c) Centrum inc Software Solutions
 *
 * $ Version 0.2
 **/

// Includes

# include <string>

# if !defined(__CRC32_H)
# define __CRC32_H
# include "FileCRC32.cpp"
# endif

# if !defined(__DISKFILE)
# define __DISKFILE

////////////////////////////
using namespace std;

namespace DiskFileBlock
{
	/////////////////////////
   // Start Class
	class DiskFile
   {
private:
		char filePath[256];
      unsigned long fileCRC;
public:
   	DiskFile(){
	   	strcpy(filePath,"");
         fileCRC = 0L;
      }
		DiskFile(char * sFilePath){
			strcpy(filePath,sFilePath);
      }

      // Externally defined functions

		void calcFileCRC();
      unsigned long getFileCRC32();
      char * getFilePath()
      { return filePath;}
 	};
   // End Class
   /////////////////////////////

   void DiskFile :: calcFileCRC()
   {
   	FileCRC32 obj(filePath);
		fileCRC = obj.CalculateFileCRC();
   }

   unsigned long DiskFile :: getFileCRC32() { return fileCRC;}
}
# endif
// End of DiskFile