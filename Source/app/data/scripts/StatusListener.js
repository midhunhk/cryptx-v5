/* StatusListener.js - listens to status of Console Program
 *
 * (c) Centrum inc Software Solutions
 * July 2008
 * $ Version 0.3.2
 **/

var checkStatusID = false;
var checkInterval = 800;
var slStatusFile  = "sl_status.st";

///////////////////////////////////////
// FUNCTION TO READ CONTENTS OF A FILE
///////////////////////////////////////

function readFileContents(file)
{	var text;
	xmlhttp = new ActiveXObject("Microsoft.XMLHTTP");
	xmlhttp.open("GET",file,true);
	xmlhttp.onreadystatechange=function()
	{
		if (xmlhttp.readyState==4)
		{ text = xmlhttp.responseText;	}
	}
	xmlhttp.send(null);
	return text;
}

function initStatusListner()
{
	
//	processStatusFile();
	checkStatusID = window.setTimeout('processStatusFile()',checkInterval);
	checkInterval = 200;
	
}
/* Status {code - state (proc_complete)}
   00 - init
   10 - enc start
   30 - no file (stop)
   11 - enc complete (stop)
   20 - dec start
   21 - dec end (stop)
   06 - crc fail (stop)
   32 - wrong password (stop)
*/

function processStatusFile()
{
	var rf = /_/g; 
	var fileContents;
	var listenComplete = false;
	var notifyStatus   = false;
	var sMessage	   = "";
	try{		
		fileContents = readFileContents(slStatusFile);
		statusData   = fileContents.split('-');
		sMessage     = statusData[1].substring(1,statusData[1].length-1);
		sMessage = sMessage.replace(rf,' '); // Replace '_' with ' '
		switch(statusData[0])
		{
			case '00' :
			case '10' :
			case '20' : notifyStatus = false; break;
			
			case '30' : 
			case '11' : 
			case '21' : 
			case '06' : 
			case '32' : listenComplete = true; notifyStatus = true; break;
			default   : notifyStatus = true;
		}
	}
	catch(e){
		// On Error Stop Processing
		alert(e.message);
		listenComplete = true;
	}
	if(notifyStatus)
		alert(sMessage);
	
	if(listenComplete){
		window.clearTimeout(checkStatusID);
		return;
	}
	checkStatusID = window.setTimeout('processStatusFile()',checkInterval);
}