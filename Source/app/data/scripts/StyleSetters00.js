/* StyleSetters00.js - Set Styles
 *
 * (c) Centrum inc Software Solutions
 * July 2008
 * $ Version 0.2
 **/

function toggleDisplay(id){ var b = geds(id);	gebid(id).style.display = (b=="")? "none" : "";}
function hideElement(id){ gebid(id).style.display = "none";}
function showElement(id){ gebid(id).style.display = ""; }
//--------------------------------

function setTextboxStyle(which,state)
{
	if(state) enableTextBox(which);
	else disableTextBox(which)
}

// Enable a TextBox
function enableTextBox(which)
{
	gebid(which).disabled = false;
	gebid(which).style.border = 'inset 2px';
	gebid(which).style.backgroundColor = '#FFFFFF';
}

// Disable a TextBox
function disableTextBox(which)
{
	gebid(which).value = '';
	gebid(which).disabled = true;
	gebid(which).style.border = 'ridge 2px';
	gebid(which).style.backgroundColor = '#f0f0f0';
}