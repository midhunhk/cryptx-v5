/* CommonMethods0.js - Common Methods Used
 * 
 * (c) Centrum inc Software Solutions
 * July 2008
 * $ Version 0.1.1
 **/

function gebid(id) {return document.getElementById(id);}
function geds(id){ return gebid(id).style.display;}

window.resizeTo(385,438);
var y = screen.availHeight/4;
var x = screen.availWidth/4;
window.moveTo(x+50,y);

function showAboutWindow()
{	alert(" CryptX 5.1 (32-bit) Encryption Utility \n(c) 2008 Centrum inc Software Solutions\n\nhttp://www.cryptx5.co.nr");	}

document.onload = function(){ gebid('txtPassword').focus();}