/* SideLiner - Main Module | Integrator
 * - Encryption Software [Console Part]
 *
 *
 * June 2008
 * @author : Midhun Harikumar
 * (c) Centrum inc Software Solutions
 *
 * $ Version  : Major 	 - 5
 * $ Version  : Minor 	 - 0.5
 * $ Version  : Revision - p0.8.8 (Build : 5.1.3.8)
 *
 * [] Block class
 * [] String <-> Hex conversions - works on text based files
 * [] Code Cleanup
 * [] Checks file status before encrypting
 * [] Somehow Code Reorganisation has enabled proper working of program
 **/

// Includes

# include <conio>
# include <stdio>
# include <string>
# include <fstream>
# include <iostream>

# include "Block.cpp"
# include "CTimer.cpp"
# include "SideLiner.h"
# include "Rijndael.cpp"
# include "DiskFileIn.cpp"
# include "DiskFileOut.cpp"

// Global Variables - Temp Placeholder

namespace SideLiner{


// CommandLine Patterns
// --------------------
// sideliner <-E> <"sourceFilePath"> <"outputFilePath"> <"origExt"> 	<"key"> [["logfile"] [-dbg/-no]]
// sideliner <-D> <"sourceFilePath"> <"outputFilePath"> ["ra5"] 		<"key"> [["logfile"] [-dbg/-no]]
// --------------------

///////////////////////////
// Applictaion Entry Point
///////////////////////////

void main(int argc,char *argv[])
{
	if(argc == 6 || argc == 7 || argc == 8)
   {
		// Process Command Line Arguments
      bool debug;
      char srcPath[512];
      char destPath[512];
      char logPath[64];
      char origExt[8];
      char key[32];
      unsigned char sPlainHash[32],appSigHash[32];
      unsigned long inputFileSize = 0L;

      strcpy(key,			argv[5]);
     	strcpy(srcPath,	argv[2]);
     	strcpy(destPath,	argv[3]);
    	strcpy(origExt,	argv[4]);
      strcpy(appSigHash,"\0");

      if(argc==7 || argc==8) strcpy(logPath,argv[6]);
      else			strcpy(logPath,"sl_Simple.log");
      debug = (argc==8)?(  (strcmp(argv[7],"-dbg")==0)?true:false):false;

      // Initialize AES Class
      Rijndael aesSig;
      aesSig.SetParameters(g_keySize);
      aesSig.StartEncryption(key);

		// Calculate the application hash using the key and convert it to hex
      // Only using half the generated length of signature
		aesSig.EncryptBlock(g_applicationSignature,sPlainHash);
      CharStr2HexStr(sPlainHash,appSigHash,8);

      unsigned char inb[512],outb[512];
      unsigned int iSizeCount = 16;							// Size of a block in bytes

      DiskFileOutBlock :: DiskFileOut simpleLog(logPath); 	// Open Simple Logfile,

      DiskFileOutBlock :: DiskFileOut slStatusFile("sl_status.st"); 			// Open Status File
      slStatusFile.writeBlock("00-{Initialising}");
      slStatusFile.closeFile();

      if(strcmp(argv[1],"-E")==0)
      {
      	/////////////////////
      	// Do Encryption

         slStatusFile.reopenFile();
	      slStatusFile.writeBlock("10-{Start_Encryption}");
   	   slStatusFile.closeFile();

			simpleLog.writeBlock("Starting Encryption...\r\n");
			simpleLog.writeBlock("Source File : ");
			simpleLog.writeBlock(srcPath);

			DiskFileIn input(srcPath);							// Initialise Source File

			// Checks if the specified input file exists
         // Not needed with GUI, but specified for completeness.
         if(input.fileOpen() == false)
         {
	         slStatusFile.reopenFile();
		      slStatusFile.writeBlock("30-{No_Source_File}");
   		   slStatusFile.closeFile();
         	if(debug) cout<<"[Error] DiskFileIn() :: NO_FILE_EXISTS";
            return;
         }

         CTimer ct1;
			simpleLog.writeBlock("\r\nStarting Time   ...");
			simpleLog.writeBlock(ct1.getFormattedTimeString());

         inputFileSize = input.getFileSize();			// Get input file size

         RapFileHeader header(origExt,		         	// Build the header
         							appSigHash,
                        		inputFileSize,
                        		input.getFileCRC32());

         if(debug) header.printContents();				// Diagnostics in debug mode

         // read each block from src, encrypt it and write it
         DiskFileOutBlock :: DiskFileOut output(destPath); 	// Open destFile,
         output.writeBlock(header);						         // write header

         Rijndael aes;
      	aes.SetParameters(g_keySize);
      	aes.StartEncryption(key);

			int nb 		 = inputFileSize / iSizeCount;			// Number of Blocks
         int padStart = inputFileSize % iSizeCount;			// Size of last block
         int readSize = iSizeCount;
         float percComplete = 0;
         unsigned char t1[32],t2[32];

			if(padStart  > 0)	nb++;

			for(int i=0;i<nb;i++)
         {
         	if(padStart>0&&i==nb-1) readSize = padStart;

            percComplete = ((i*100)/nb);
            cout<<"\r   ";  // Whitewash
            cout<<"\r "<<percComplete<<" %";

		      aes.EncryptBlock(input.readBlock(readSize),t1);	// Encrypt it

            t1[16] = '\0';
            CharStr2HexStr(t1,outb,16);							// convert to hex
				outb[32] = '\0';
				Block aBlock(outb);										// Create a Block
      		output.writeBlock(aBlock);								// Write it down

	      }
         cout<<"\r      ";  // Whitewash
         cout<<"\r 100 %";
			output.closeFile();

         // Calculate the Duration
         CTimer ct2;
         CTimer timeEncr = ct2 - ct1;
			simpleLog.writeBlock("\r\nCompletion Time ...");
			simpleLog.writeBlock(ct2.getFormattedTimeString());
			simpleLog.writeBlock("\r\nProcess Duration...");
			simpleLog.writeBlock(timeEncr.getFormattedTimeString());

         slStatusFile.reopenFile();
	      slStatusFile.writeBlock("11-{Encryption_Complete}");
   	   slStatusFile.closeFile();

			// End of Encryption
         /////////////////////
      }
      else if(strcmp(argv[1],"-D")==0)
      {
      	/////////////////////
      	// Do Decryption

         // Open Source File
         // Read Header
         // If Valid format, version etc
         //		Check the signature with currently supplied password
         //			Get oe from header and append it to destFileName
         //			if match, decrypt file block by block
         //				Using payloadLength from header, skip the padded bytes,
         //				in the final block

			DiskFileInBlock :: DiskFileIn input(srcPath);								// Open Source File

         RapFileHeader r = input.readHeader();				// Read Header
         inputFileSize   = r.getPayloadSize();

			// TODO : If valid RA5 File process

			if(debug) r.printContents();	// Diagnostics

         // Put Extension to the outputfile by reading from header
         strcat(destPath,".");
         strcat(destPath,r.getOriginalExtension());

         // Create the output file
         DiskFileOutBlock :: DiskFileOut output(destPath);

			// Check sig from rap file and calculated sig for key
         // ! No need to chk for valid RA5 as this test will most propably fail for other types of files
         if(strcmp(r.getCryptxSignature(),appSigHash) == 0)
         {
      	   slStatusFile.reopenFile();
		      slStatusFile.writeBlock("20-{Start_Decryption}");
	   	   slStatusFile.closeFile();

         	if(debug) cout<<"\nThe Password is correct\n"; // DEBUG
            Rijndael aes;
            aes.SetParameters(g_keySize);
		      aes.StartDecryption(key);

            unsigned char t3[32];

				int nb 		  = inputFileSize / iSizeCount; 	// Number of Blocks
   	      int padStart  = inputFileSize % iSizeCount;
            int writeSize = iSizeCount;
				if(padStart  > 0)
   	      	nb++;

				for(int i=0;i<nb;i++){

	         	if(padStart>0&&i==nb-1) writeSize = padStart;

            	Block redBlock = input.readABlock();		// Read a special block from src
					strcpy(inb,redBlock.getBlockData());		// copy the data into inb

					HexStr2CharStr(inb,t3,32);
		   	   aes.Decrypt(t3,outb,2);					// try to decrypt it

               outb[writeSize+1] = '\0';
      			output.writeBlock(outb,writeSize);
		      }
            output.closeFile();

   	      slStatusFile.reopenFile();
		      slStatusFile.writeBlock("21-{End_Decryption}");
   		   slStatusFile.closeFile();

            // Calculate the final CRC
            if( r.getPayloadCRC() == output.getFileCRC()){
            	// CRC Match
					if(debug)
               	cout<<"\nCRC Match.";
            }
            else{
		         if(debug)
	  	   	   	cout<<"\nCRC Fail. Expecting "<<r.getPayloadCRC()<<" ("<<output.getFileCRC()<<")";
			       slStatusFile.reopenFile();
		   		 slStatusFile.writeBlock("06-{CRC_Fail}");
			   	 slStatusFile.closeFile();
            }
         }
         else{
	         if(debug)
   	      	cout<<"Wrong Pasword";
		       slStatusFile.reopenFile();
	   		 slStatusFile.writeBlock("32-{Wrong_Password}");
		   	 slStatusFile.closeFile();
         }
      }
   }
   else
   {
   	// Invalid number of arguments
      cout<<"  CryptX 5 Encryption Software"<<endl;
      cout<<"  Sideliner build ["<<g_applicationVersion<<"]"<<endl;
      cout<<endl<<"Command line usage : "<<endl;
		cout<<"\tsideliner <-E> <\"sourceFilePath\"> <\"outputFilePath\"> <\"origExt\"> <\"key\"> [[\"logfile\"] [-dbg/-no]]"<<endl;
		cout<<"\tsideliner <-D> <\"sourceFilePath\"> <\"outputFilePath\"> <\"origExt\"> <\"key\"> [[\"logfile\"] [-dbg/-no]]"<<endl;
   }
}

}/* end namespace */
