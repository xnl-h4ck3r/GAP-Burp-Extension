<html><h1>GAP by @xnl_h4ck3r</h1>
<hr><br>
<b>This is an evolution of the original getAllParams extension for Burp. Not only does it find more potential parameters for you to investigate, but it also finds potential links to try these parameters on, and produces a target specific wordlist to use for fuzzing. 
This code is far from perfect, but any constructive criticism is very much welcome! I hope this tool helps you.
</b>
<br>
<h3>Acknowledgments:</h3> 
Respect and thanks go to @HolyBugx for help with ideas, testing and patience!<br>
A shout out to Gerben Javado and his amazing tool <b>Link Finder</b> who's regular expression (regex) provided the starting point for the Link mode in GAP.

<h1>How to Install</h1>
<ol>
<li>Visit <a href="https://www.jython.org/download">Jython Offical Site</a>, and download the latest stand alone JAR file, e.g. <code>jython-standalone-2.7.4.jar</code>.</li>
<li>Open Burp, go to <b>Extensions</b> -> <b>Extension Settings</b> -> <b>Python Environment</b>, set the <b>Location of Jython standalone JAR file</b> and <b>Folder for loading modules</b> to the directory where the Jython JAR file was saved.</li>
<li>On a command line, go to the directory where the jar file is and run <code>java -jar jython-standalone-2.7.4.jar -m ensurepip</code>.</li>
<li>Download the <code>GAP.py</code> and <code>requirements.txt</code> from this project and place in the same directory.</li>
<li>Install Jython modules by running <code>java -jar jython-standalone-2.7.4.jar -m pip install --no-cache-dir --no-compile -r requirements.txt</code>.</li>
<li>Go to the <b>Extensions</b> -> <b>Installed</b> and click <b>Add</b> under <b>Burp Extensions</b>.
<li>Set <b>Extension type</b> to <b>Python</b> and select the <code>GAP.py</code> file</li>
<li>Click <b>Next</b> and you're good to go <b>&#129304;</b></i>
</ol>
<h1>How to Run</h1>
You can run GAP from a single request/response, or multiple, from any context in Burp. For example, you can run for a single request in Repeater, a group of requests in Proxy History, request in the Site Map contents, etc. However, the most common option will probably be from the Site Map tree view. <b>IMPORTANT: Make sure you have scope set before running from this context.</b><br><br>
On the <b>Target -> Site map</b> tab of Burp you can select a specific host, a selection of hosts (holding down <i>Ctrl</i> or <i>Shift</i>), or all hosts (using <i>Ctrl-A</i>), or even select a specific sub folder or specific endpoints. 
Once the required endpoints are selected, right click and select <b>Extensions -> GAP</b> to run the tool.
Go to the <b>GAP</b> tab and see the results. What gets returned will depend on the options selected, and these will all be described below.
For very large projects (and depending on what options were selected), it can sometimes take GAP a little while to run. If for some reason it hasn't completed and you want to cancel the current run to change options for example, you can do this by pressing the <b>CANCEL GAP</b> button.
If you try running GAP again while it is still running, it will CANCEL the current run before starting the new one.
<p>
<h1>GAP Mode</h1>
There are 3 different modes for GAP, <b>Parameters</b>,<b>Links</b> and <b>Words</b>. They can either be run separately, or together, depending on what you select.
What each mode does will be explained below, but if you don't need all enabled then unselecting them can use less memory and get results back quicker.

<h1>Parameters Mode</h1>

When the GAP Mode of Parameters is selected then GAP will try to find as many potential parameters based the following options:

<ul>
<li><b>Include URL path words?</b> - The words in the response URL path are included as potential parameters if the URL is in scope.</li>
<li><b>Report "sus" parameters?</b> - If a "sus" parameter is identified, a Burp custom Issue will be raised (unavailable in Burp Community Edition). There will be no markers in the Request/Response of the Issue showing where the named parameter can be found because including this functionality seriously increases the time GAP can take to run, so this is not a feature at the moment. For Burp Community Edition, the details of the parameter will be written to the extension output.</b></li>
<li><b>Inc. Tentative?</b> - If a "sus" parameter is identified, the <b>Report "sus" parameters</b> option is checked, and the confidence is <b>Tentative</b>, this option determines whether it is raised or not.</li>
</ul>

<h2>Request Parameters</h2>
These are mainly parameters that Burp itself identifies from HTTP requests and are part of the Burp Extender API <a href="https://portswigger.net/burp/extender/api/burp/iparameter.html">IParameter interface</a>
<ul>
<li><b>Query string params</b> - PARAM_URL; a parameter within the URL query string</li>
<li><b>Message body params</b> - PARAM_BODY; a parameter within the message body </li>
<li><b>Param attribute in multi-part message body</b> - PARAM_MULTIPART_ATTR; the value of a parameter attribute within a multi-part message body (such as the name of an uploaded file)</li>
<li><b>JSON params</b> - PARAM_JSON; an item of data within a JSON structure</li>
<li><b>Cookie names</b> - PARAM_COOKIE; an HTTP cookie name</li>
<li><b>Items of data in XML structure</b> - PARAM_XML</li>
<li><b>Value of tag attribute in XML structure</b> - PARAM_XML_ATTR</li>
</ul>
Additionally, GAP will also report any parameters in the Request where the Burp API doesn't always successfully detect them:
<ul>
<li>JSON format</li>
<li>GraphQL request (COMING SOON)</li>
<li>XML request (COMING SOON)</li>
</ul>

<h2>Response Parameters</h2>

These are potential parameters that can be found in the HTTP responses. These are identified by GAP itself rather than through the Burp Extender API.

<ul>
<li><b>JSON params</b> - if the response has a MIME type of JSON then the Key names will be retrieved</li>
<li><b>Value of tag attributes in XML structure</b> - if the response has a MIME type of XML then the XML attributes are retrieved</li>
<li><b>Name and Id attributes of HTML input fields</b> - if the response has a MIME type of HTML OR JAVASCRIPT (because it maybe building HTML) then the value of the NAME and ID attributes of any INPUT or TEXTAREA tags are retrieved</li>
<li><b>Javascript variables and constants</b> - javascript variables set with <code>var</code>, <code>let</code> or <code>const</code> are retrieved. Also, if there is a variable set with one of those keywords that is set to a nested object, the keys for that object are also returned as parameters. In addition to this, any key value is nested objects for <code>dataLayer.push</code> are also returned. <b>NOTE: Improvements are needed to retrieve more variables as there are many ways that these can be declared and difficult to retrieve all from regex.</b></li>
<li><b>Params from links found</b> - THIS OPTION IS ONLY ENABLED IF LINKS MODE IS ALSO USED. Any URL query string parameters in potential Links found will be retrieved, only if they are clearly in scope, or there is just a path and no way of determining if it is in scope.</li>
</ul>

<h1>Links Mode</h1>

When the GAP Mode of Links is selected then GAP will try to find possible links based on the following. Also, only requests of a certain <i>Content-Type</i> are checked for potential links. This is determined by the constant <code>CONTENTTYPE_EXCLUSIONS</code> in the code (these are types such as images, video, audio, fonts, etc.)

<ul>
<li><b>Prefix with selected target(s)</b> - If checked, the root of each target selected in the Site Map will be prefixed to any links found that do not have a domain, e.g. <code>/api/user/1</code></li>
<li><b>Prefix with link(s)</b> - If checked, the value(s) in the text field will be prefixed to any links found that do not have a domain, e.g. <code>/api/user/1</code>. Multiple domains can be provided, separated by a semicolon, e.g. <code>http://example.com;https://sub.example.com</code></li>
<li><b>Also include un-prefixed links</b> - If the <b>Prefix with selected target(s)</b> or <b>Prefix with link(s)</b> option is checked then this option can be checked to include the original un-prefixed link in addition to the prefixed link.</li>
<li><b>Include site map endpoints?</b> - This will include endpoints from the Burp Site map (what was selected) in the potential Link list, if they are in scope.</li>
<li><b>Include relative links?</b> - If checked, links found that start with `./` or `../` will be included in the results.</li>
<li><b>Link exclusions</b> - If the option is selected it will be applied when run. The text field contains a comma separated list of values. If any of these values exists in a potential link found, then it will be excluded from the final list. There is a initial default list determined by the <code>DEFAULT_EXCLUSIONS</code> constant, but you can change this and save your settings. If the option is not selected, all links will be returned.</li>
</ul>

<h1>Words Mode</h1>

When the GAP Mode of Words is selected then GAP will produce a target specific wordlist from the responses searched.

<ul>
<li><b>Create lowercase words?</b> - Any word found that contains an uppercase letter will also be added as an all lowercase word.</li>
<li><b>Create singular/plural word?</b> - If checked, then for each word found, a suitable singular or plural version will also be added to the output.</li>
<li><b>Include HTML comments?</b> - If checked, all words within HTML comments will be considered.</li>
<li><b>Include IMG ALT attribute?</b> -If checked, all words with the <code>ALT</code> attribute of <code>IMG</code> tags will be considered.</li>
<li><b>Include words with digits?</b> - If un-checked, then any words with numeric digits will be excluded from output.</li>
<li><b>Include URL path words?</b> - Any path words in selected links will be added as words.</li>
<li><b>Include potential params</b> - This option is only shown if the Parameters Mode is enabled. If selected, all potential params will also be added to the word list.</li>
<li><b>Maximum length of words</b> - The maximum length of words that will be output (this excludes plurals of minimum length words). This can be a minimum of 3.</li>
<li><b>Stop words</b> - The term <b>stop words</b> comes from Natural Language Processing where they are common words that will be excluded from content. If a word exists in this list before running, then it will be excluded from output.</li>
</ul>

In addition to the options above, words will be taken from all responses with certain conditions:

<ul>
<li>Only responses with content types are searched. The defaults are <code>text/html</code>,<code>application/xml</code>,<code>application/json</code>,<code>text/plain</code>,<code>application/xhtml+xml</code>,<code>application/ld+json</code>,<code>text/xml</code></li>
<li>Words from <code>&lt;meta&gt;</code> tag content where:
    <ul>
    <li>Property is <code>og:title</code>, <code>og:description</code>, <code>title</code>, <code>og:site_name</code> or <code>fb:admins</code></li>
    <li>Name is <code>description</code>, <code>keywords</code>, <code>twitter:title</code>, <code>twitter:description</code><code>application-name</code>, <code>author</code>, <code>subject</code>, <code>copyright</code>, <code>abstract</code>, <code>topic</code>, <code>summary</code>, <code>owner</code>, <code>directory</code>, <code>category</code>, <code>og:title</code>, <code>og:type</code>, <code>og:site_name</code>, <code>og:description</code>, <code>csrf-param</code>, <code>apple-mobile-web-app-title</code>, <code>twitter:label1</code>, <code>twitter:data1</code>, <code>twitter:label2</code>, <code>twitter:data2</code> or <code>twitter:title</code></li>
    </ul>
<li>Words from <code>&lt;link&gt;</code> tag title where:
    <ul>
    <li>Rel is <code>alternate</code>, <code>index</code>, <code>start</code>, <code>prev</code>, <code>next</code> or <code>search</code></li>
    </ul>
<li>Words from the rest of the inner HTML of the page, excluding tags <code>&lt;style&gt;</code>, <code>&lt;script&gt;</code> and <code>&lt;link&gt;</code></li>
</ul>

<h1>GAP Output</h1>
Below is an explanation of the output given when GAP has completed running. When running has been completed, you can click the right mouse button in the parameter, words or links pane to get a <code>Copy</code> link. Clicking this will copy whatever is in the pane to your clipboard.

<h2>Potential Parameters</h2>
<ul>
<li><b>Potential parameters found</b> - This text are will show all unique potential parameters, one per line.</li>
<li><b>Show origin</b> - If this feature is ticked, the potential parameter will be followed by the HTTP request endpoint (in square brackets) that the parameter was found in. A parameter could have been found in more than one request, so this view can show duplicate links, one per origin endpoint.</li>
<li><b>Show "sus"</b> - If this feature is ticked, only potential parameters that are "sus" are shown followed by the associated vulnerability type(s) (in square brackets). <b>NOTE: If you right click and select <code>Copy</code> you will have the parameter names WITHOUT the vuln types copied to your clipboard.</b></li>
<li><b>Show query string with value</b> - This checkbox can be used to switch between the list of parameters and a concatenated query string with all parameters with a value given in the following text box.</li>
<li><b>Param Value</b> - This defaults to XNLV and is a value that is used to create the concatenated query string, with each parameter given this value followed by a unique number of the parameter. This query string can be used to manually append to a URL and check for reflections.</li>
</ul>
<h2>Potential Links</h2>
<ul>
<li><b>Potential links found</b> - This text area will show potential links found. Without any of the other options described below selected, all unique endpoints found are displayed, one per line.</li>
<li><b>Show origin endpoint</b> - If this feature is ticked, the potential link will be followed by the HTTP request endpoint (in square brackets) that the link was found in. A link could have been found in more than one request, so this view can show duplicate links, one per origin endpoint.</li>
<li><b>In scope only</b> - If this feature is ticked, and the potential links contain a host, then this link will be checked against the Burp Target Scope. If it is not in scope then the link will be removed from the output. <b>NOTE: If it is not possible to determine the scope (e.g. it may just be a path without a host) then it will be included as in scope to avoid omitting anything potentially useful.</b></li>
<li><b>Link filter</b> - any value entered in the Filter input field followed by <b>ENTER</b> or pressing <b>Apply filter</b> will determine which links will be displayed. This can depend on the values of the following two options:</li>
<li><b>Negative match</b> - If selected, any link containing the Filter text will NOT be displayed. If unselected, then only links containing the filter will be displayed.</li>
<li><b>Case sensitive</b> - If selected, the value is the Filter input field will be case sensitive when determining which Links to display.</li> 	
</ul>
The filter is something that is applied after GAP has run. It allows you to look for specific things when there are many results. For example, enter <code>.js</code> to only show the links to javascript files. As soon as you clear the filter, the original results are redisplayed.<br>
<br>
An additional feature of GAP is to automatically include links of valid <code>.js.map</code> (javascript source map) files. These are identified by responses that contain the <code>//# sourceMappingURL</code> line, or have a HTTP header of <code>SourceMap</code> or <code>X-SourceMap</code>.<br>
<br>
To find links, a complex regex is used to look for different formats and contexts for potential links and files. This regex was initially based on the one used in <b>Link Finder</b> by Gerben Javado, but has been evolved to try and identify more with minimal false positives.<br>
<br>
If you have the <b>Show origin endpoint</b> options unchecked and the <b>In scope only</b> option checked, then when you right click the pane, you will get another menu option of <b>Request all prefixed URLs and send to Site Map</b>. Clicking this will request all URLs shown in the current pane (so can be filtered with <b>Link filter</b> too) and make a <code>GET</code> request for each URL. The URLs will be requested in 2 separate threads, with 10 milliseconds between each request, and they will be added to the <b>Site Map</b>.<br>
<b>NOTE: Sometimes java errors can be written to the extensions Error tab if a hoist is unreachable. There doesn't seem to be a way to catch these, but they can be safely ignored.</b><br>
When requests are being made, you can right click on the pane and select the <b>Cancel all requests being made</b> menu item to stop all requests previously scheduled.<br>
<h2>Words</h2>
<ul>
<li><b>Words found</b> - This text are will show all unique words, one per line.</li>
<li><b>Show origin</b> - If this feature is ticked, the words will be followed by the HTTP request endpoint (in square brackets) that the word was found in. A word could have been found in more than one request, so this view can show duplicate links, one per origin endpoint. If the word was generated by GAP (e.g. a plural or singular version) then it will be followed by <code>[GAP]</code> instead of an origin endpoint.</li>
</ul>

<h1>Other options</h1>
<ul>
<li><b>Show contextual help</b> - If selected, hovering over any features of GAP will give contextual help for that feature.</li>
<li><b>Auto save output to directory</b> - If this option is checked then when GAP completes a run, a file will be created with the potential parameters, with potential links, and target specific wordlist. These files will be created in the specified directory. If the directory is invalid then the users home directory will be used. 
<li><b>Choose...</b> - the button can be used to select the required directory to store output files. </li>
</ul>
If the <b>Auto save output to directory</b> option is checked, then files are written as follows:<p>
<ul>
<li>Create a sub folder for each root in the target site that was selected in Site Map</li>
<li>Create a file in the main folder with the name of the Burp project and timestamp, e.g. if the project is called <code>target</code>, the files might be <code>target_20230416_133700_links.txt</code>, <code>target_20230416_133700_parans.txt</code> and <code>target_20230416_133700_words.txt</code> where <code>20230416</code> is the current date in <code>YYYYMMDD</code> format and <code>133700</code> is the current time in <code>HHMMSS</code> format. These files will contain what was found for ALL roots selected.</li>
<li>Within each sub folder, the files will only contain findings for that particular root. If there are no findings for a mode, then a file will not be created for that mode.</li>
</ul>
<b>NOTE:</b> The project name is taken from the Burp title. If you use the <b>Sharpener</b> Burp Extension then changing the Title will affect the naming of the files.
<p>

<h1>GAP Settings</h1>
When GAP is first started, it will start with default settings. 
Any changes made to the configuration settings of GAP can be saved for future use by clicking the <b>Save options</b> button.
If for any reason you want to revert to the default configuration options, you can click the <b>Restore defaults</b> button.
<p>
<h1>Troubleshooting and Feedback</h1>
<p>It is hard to design GAP to display all controls for all screen resolutions and font sizes. I have tried to deal with the most common setups, but if you find you cannot see all the controls, you can hold down the <code>Ctrl</code> button and click the GAP logo header image to remove it to make more space.</p>
If you have any problems with GAP, you can report an issue on Github. Before you report an issue, please look at the <b>Extender -> Extensions</b> tab in Burp, click on the GAP extension in the list and include details of any output displayed on the <b>Errors</b> tab with your issue. If you know of a parameter or link that you believe GAP should/shouldn't have identified then please provide as much info as possible, e.g. the options you had selected, the relevant endpoint, etc. <br>

<p>
<h1>Important Notes</h1>
If you don't need one of the modes, then un-check it as results will be quicker.

If you run GAP for one or more targets from the Site Map view, don't have them expanded when you run GAP... unfortunately this can make it a lot slower. It will be more efficient if you run for one or two target in the Site Map view at a time, as huge projects can have consume a lot of resources.

If you want to run GAP on one of more specific requests, do not select them from the Site Map tree view. It will be a lot quicker to run it from the Site Map Contents view if possible, or from proxy history.

It is hard to design GAP to display all controls for all screen resolutions and font sizes. I have tried to deal with the most common setups, but if you find you cannot see all the controls, you can hold down the <code>Ctrl</code> button and click the GAP logo header image to remove it to make more space.</p>

<p>
<h1></h1>
Thank you for trying out GAP!<br>
Good luck and good hunting!
If you really love the tool (or any others), or they helped you find an awesome bounty, consider <a href="https://ko-fi.com/xnlh4ck3r">BUYING ME A COFFEE!</a> ☕ (I could use the caffeine!)<p>
@xnl-h4ck3r
<b>&#129304;</b>
</html>
