# Burp Extensions

This is a collection of extensions to Burp Suite that I have written.

## getAllParams.py - Version 1.1

This is a python extension that runs in Portswigger's Burp Suite and parses an already crawled sitemap to build a custom parameter list. 
It also adds common parameter names that could be useful in the final list used for fuzzing.

Although it has a different function, the code was based on the why-cewler.py extension by Ianmaster53
(https://gist.github.com/lanmaster53/a0d3523279f3d1efdfe6d9dfc4da0d4a) just as a base template.

Usage:
1. Point Burp Suite to Jython in the Extender > Options tab.
2. Install this extension manually in the Extender > Extensions tab.
3. Change any options on the "Get All Params" tab.
4. Right-click on any element in the Target tab's hierarchical sitemap.
5. Select the Extensions > Get All Params context menu item.
6. Go to the "Get All Params" tab to see the results.

If the option to save output to a file is selected then a file of all paramaters will be created in the users home directory (or Documents for Windows) 
with the name "{TARGET}_getAllParams.txt"
The extension Output tab will show a combined string of all parameters and a test value (default of of XNLV? - where ? is a unique number)
This string can be used in requests and then Burp history searched for any relection of XNLV

REQUEST PARAMETERS:
The following types of paramters with in the Burp IParamater interface can be retunred (depending on selected options):
- PARAM_URL (0) - Used to indicate a parameter within the URL query string.
- PARAM_BODY (1) - Used to indicate a parameter within the message body.
- PARAM_COOKIE (2) - Used to indicate an HTTP cookie.
- PARAM_XML (3) - Used to indicate an item of data within an XML structure.
- PARAM_XML_ATTR (4) - Used to indicate the value of a tag attribute within an XML structure.
- PARAM_MULTIPART_ATTR (5) - Used to indicate the value of a parameter attribute within a multi-part message body (such as the name of an uploaded file).
- PARAM_JSON (6) - Used to indicate an item of data within a JSON structure.

RESPONSE PARAMETERS:
- JSON parameters (Thanks to contribution by Pichik)
- XML paramaters (Thanks to contribution by Pichik)
- Words from URL paths, if you are using this to generate a wordlist (Thanks to contribution by Pichik)
- Name and Id attribute from HTML Input fields
- Javascript variables and constants in ALL types of reponses (JS vars could be in the html, script and even JSON response within a .js.map file)
- Meta tag Name attribute
