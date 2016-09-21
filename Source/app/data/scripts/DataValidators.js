/* DataValidators.js - Validator methods
 *
 * (c) Centrum inc Software Solutions
 * July 2008
 * $ Version 0.2
 **/

// Validate a file name
function isValidFileName(sFileName)
{
	var r = /["\\\/\*:\?<>|]/;	// to test for proper file name
	if(r.test(sFileName)){
		alert('The file name cannot contain any of the following characters:\n \t \\ / : * ? \ " < > |'); 
		return false;
	}
	return true;
}