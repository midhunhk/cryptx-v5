/* CommandLineGen.js - Generate Command Line Parameters
 *
 * (c) Centrum inc Software Solutions
 * July 2008
 * $ Version 0.5.2
 **/
 
// CommandLine Patterns
// --------------------
// sideliner <-E> <"sourceFilePath"> <"outputFilePath"> <"origExt"> <"key"> [["logfile"] [-dbg/-no]]
// sideliner <-D> <"sourceFilePath"> <"outputFilePath"> ["ra5"] 	<"key"> [["logfile"] [-dbg/-no]]

function getCommandLineParams()
{
	var filePath    = gebid("txtFile").value;
	var txtCommand  = "data\\Sideliner.exe ";
	var txtPassword = gebid("txtPassword").value;
	if(txtPassword == ""){ 
		alert("Please enter a password"); 
		return;
	}
	txtPassword = getProperPasswordString(txtPassword);
		
	if(filePath)
	{
		var fileDirectory 	= filePath.substring(0,filePath.lastIndexOf('\\')+1);
		var fileName		= filePath.substring(filePath.lastIndexOf('\\')+1,filePath.lastIndexOf('.'));
		var fileType		= (filePath.substring(filePath.lastIndexOf('.')+1,filePath.length)).toLowerCase();

		// Check for custom folder name or file name
		var outputDirectory = fileDirectory;
		var outputFileName  = fileName;
		if(useCustomDirectory()){
			outputDirectory =  gebid('txtCustomDir').value;
			if(outputDirectory == ''){
				alert("Please Specify Output Directory...");
				return;
			}
			// Append \ to dir name if not specified
			if(outputDirectory.charAt(outputDirectory.length) != '\\')
				outputDirectory += '\\';
		}
		if(useCustomFileName()){
			outputFileName = gebid('txtCustomFile').value;
			if(outputFileName == ''){
				alert("Please Specify Output File Name...");
				return;
			}
			if(isValidFileName(outputFileName) == false) return false;
		}
		var outputFilePath  = outputDirectory + outputFileName;

		if(fileType == "ra5")
		{
			/////////////////////////
			// Decryption To Be Done
			/////////////////////////
			txtCommand += '-D "'  + filePath + '" ';
			txtCommand += '"'	  + outputFilePath+'" ';
			txtCommand += ' ra5 ' +'"' + txtPassword + '" ';

			/* Uncomment for Debugging */
			txtCommand += ' "customLogFile.log" -dbg'
			/**/
		}
		else
		{
			/////////////////////////
			// Encryption to be done
			/////////////////////////
			outputFilePath += '.ra5';
			txtCommand += '-E "' + filePath + '" ';
			txtCommand += '"'	 + outputFilePath+'" ';
			txtCommand += '"' 	 + fileType + '" '
			txtCommand += '"' 	 + txtPassword + '" ';
			
			/* Uncomment for Debugging */
			txtCommand += ' "customLogFile.log" -dbg'
			/**/
		}
		// initialise the Status listener here
		//
		initStatusListner();
		return txtCommand;
	}
	else
		alert("No File Selected...");
	return "";
}

// get Proper length password
// TODO : Hash it or do MD5 for added protection.
function getProperPasswordString(pwd)
{
	// test for proper lengths and add padding if needed
	var len = pwd.length;
	var sPass = pwd;
	if(len <8){ // pad
		for(i=len;i<8;i++)
			sPass += '*';
	}
	if(len>8)
		sPass =sPass.substring(0,8);		
	return sPass;
}
// Check CustomDirectory
function useCustomDirectory()
{ return gebid("chkCustomDir").checked;}

// Check CustomFileName
function useCustomFileName()
{ return gebid("chkCustomFile").checked;}