'''
Get All Params by /XNL-h4ck3r (@xnl_h4ck3r)

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
The following types of paramters within the Burp IParamater interface can be retunred (depending on selected options) from the Request:
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
- Javascript variables and constants in HTML or Script
- Meta tag Name attribute

'''

from burp import (IBurpExtender, IContextMenuFactory, ITab)
from javax.swing import (JMenuItem, GroupLayout, JPanel, JCheckBox, JTextField, JLabel, JButton, JScrollPane, JTextArea, ScrollPaneConstants)
from java.util import ArrayList
from datetime import datetime
from urlparse import urlparse 
from java.io import PrintWriter
from java.awt import Color
from java.awt import Font
import os
import platform
import re
import pickle
import threading

COMMON_PARAMS = ['page', 'callback', 'next', 'prev', 'previous', 'ref', 'go', 'return', 'goto', 'r_url', 'returnurl', 'returnuri', 'location', 'locationurl', 'retunr_url', 'goTo', 'r_Url', 'r_URL', 'returnUrl', 'returnURL', 'returnUri', 'retunrURI', 'locationUrl', 'locationURL', 'return_Url', 'return_URL', 'site', 'debug', 'active', 'admin', 'id' ]

PARAM_URL = 0
PARAM_BODY = 1
PARAM_COOKIE = 2
PARAM_XML = 3
PARAM_XML_ATTR = 4
PARAM_MULTIPART_ATTR = 5
PARAM_JSON = 6

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):
    '''
    BurpExtender Class as per Reference API.
    '''

    def registerExtenderCallbacks(self, callbacks):
        '''
        Registers the extension and initializes the root URLs and parameter list sets.
        '''
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        self.context = None
        self.roots = set()
        self.param_list = set(COMMON_PARAMS)
        callbacks.setExtensionName("Get All Params")
        callbacks.registerContextMenuFactory(self)

        # define all settings
        self.lblWhichParams = JLabel("Select param types you want to retrieve:")
        self.lblWhichParams.setFont(Font('Tahoma', Font.BOLD, 14))
        self.lblWhichParams.setForeground(Color(235,136,0))
        self.lblRequestParams = JLabel("REQUEST PARAMETERS")
        self.cbParamUrl = self.defineCheckBox("Query string params")
        self.cbParamBody = self.defineCheckBox("Message body params")
        self.cbParamMultiPart = self.defineCheckBox("Param attribute within a multi-part message body")
        self.cbParamJson = self.defineCheckBox("JSON params")
        self.cbParamCookie = self.defineCheckBox("Cookie names", False)
        self.cbParamXml = self.defineCheckBox("Items of data within an XML structure", False)
        self.cbParamXmlAttr = self.defineCheckBox("Value of tag attributes within XML structure", False)
        self.lblResponseParams = JLabel("RESPONSE PARAMETERS")
        self.cbParamJSONResponse = self.defineCheckBox("JSON params", False)
        self.cbParamXMLResponse = self.defineCheckBox("Value of tag attributes within XML structure", False)
        self.cbParamInputField = self.defineCheckBox("Name and Id attributes of HTML Input fields", False)
        self.cbParamJSVars = self.defineCheckBox("Javascript variables and constants", False)
        self.cbParamMetaName =self.defineCheckBox("Name attribute of Meta tags", False)

        self.lblOutputOptions = JLabel("Output options:")
        self.lblOutputOptions.setFont(Font('Tahoma', Font.BOLD, 14))
        self.lblOutputOptions.setForeground(Color(235,136,0))
        self.cbIncludeCommonParams = self.defineCheckBox("Include the list of common params in list (e.g. used for redirects)?", True)
        self.cbIncludePathWords = self.defineCheckBox("Include URL path words in parameter list?", False)
        self.cbSaveFile = self.defineCheckBox("Save file to home directory (or Documents folder on Windows)?")
        self.cbShowQueryString = self.defineCheckBox("Build concatenated query string?")
        self.lblQueryStringVal = JLabel("Concatenated query string param value")
        self.inQueryStringVal = JTextField(8)
        self.grpValue = JPanel()
        self.grpValue.add(self.lblQueryStringVal)
        self.grpValue.add(self.inQueryStringVal)

        self.lblParamList = JLabel("The latest list of params found:")
        self.outParamList = JTextArea("")
        self.outParamList.setLineWrap(True)
        self.outParamList.setEditable(False)
        self.scroll_outParamList = JScrollPane(self.outParamList)
        self.scroll_outParamList.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS)
        self.lblQueryString = JLabel("The latest generated query string of all parameters:")
        self.outQueryString = JTextArea("")
        self.outQueryString.setColumns(50)
        self.outQueryString.setLineWrap(True)
        self.outQueryString.setEditable(False)
        self.scroll_outQueryString = JScrollPane(self.outQueryString)
        self.scroll_outQueryString.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS)

        self.lblCount = JLabel("")
        self.lblCount.setForeground(Color(235,136,0))

        self.btnSave = JButton("Save Options", actionPerformed=self.saveConfig)
        self.btnRestore = JButton("Restore Defaults", actionPerformed=self.resetConfig)
        self.grpConfig = JPanel()
        self.grpConfig.add(self.btnSave)
        self.grpConfig.add(self.btnRestore)

        # definition of config tab
        self.tab = JPanel()
        layout = GroupLayout(self.tab)
        self.tab.setLayout(layout)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
     
        # Restore config settings
        self.restoreConfig()

        # If the query string param value doesn't exist, set it to the default
        if self.inQueryStringVal.text == "":
            self.inQueryStringVal.text = "XNLV"

        layout.setHorizontalGroup(
            layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup()
                    .addComponent(self.lblWhichParams)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup()
                            .addComponent(self.lblRequestParams)
                            .addComponent(self.cbParamUrl)
                            .addComponent(self.cbParamBody)
                            .addComponent(self.cbParamMultiPart)
                            .addComponent(self.cbParamJson)
                            .addComponent(self.cbParamCookie)
                            .addComponent(self.cbParamXml)
                            .addComponent(self.cbParamXmlAttr)
                        )
                        .addGroup(layout.createParallelGroup()
                            .addComponent(self.lblResponseParams)
                            .addComponent(self.cbParamJSONResponse)
                            .addComponent(self.cbParamXMLResponse)
                            .addComponent(self.cbParamInputField)
                            .addComponent(self.cbParamJSVars)
                            .addComponent(self.cbParamMetaName)
                        )
                    )
                    .addComponent(self.lblOutputOptions)
                    .addComponent(self.cbIncludePathWords)
                    .addComponent(self.cbIncludeCommonParams)
                    .addComponent(self.cbSaveFile)
                    .addComponent(self.cbShowQueryString)
                    .addComponent(self.grpValue, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self.grpConfig, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self.lblQueryString)
                    .addComponent(self.scroll_outQueryString, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                )
                .addGroup(layout.createParallelGroup()
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(self.lblParamList)
                        .addComponent(self.lblCount)
                    )
                    .addComponent(self.scroll_outParamList)
                )
            )
        
        layout.setVerticalGroup(
           layout.createParallelGroup()
            .addGroup(layout.createParallelGroup()
                .addGroup(layout.createSequentialGroup()
                    .addComponent(self.lblWhichParams)
                    .addGroup(layout.createParallelGroup()
                        .addGroup(layout.createSequentialGroup()
                            .addComponent(self.lblRequestParams)
                            .addComponent(self.cbParamUrl)
                            .addComponent(self.cbParamBody)
                            .addComponent(self.cbParamMultiPart)
                            .addComponent(self.cbParamJson)
                            .addComponent(self.cbParamCookie)
                            .addComponent(self.cbParamXml)
                            .addComponent(self.cbParamXmlAttr)
                        )
                        .addGroup(layout.createSequentialGroup()
                            .addComponent(self.lblResponseParams)
                            .addComponent(self.cbParamJSONResponse)
                            .addComponent(self.cbParamXMLResponse)
                            .addComponent(self.cbParamInputField)
                            .addComponent(self.cbParamJSVars)
                            .addComponent(self.cbParamMetaName)
                        )
                    )
                    .addComponent(self.lblOutputOptions)
                    .addComponent(self.cbIncludePathWords)
                    .addComponent(self.cbIncludeCommonParams)
                    .addComponent(self.cbSaveFile)
                    .addComponent(self.cbShowQueryString)
                    .addComponent(self.grpValue, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self.grpConfig, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self.lblQueryString)
                    .addComponent(self.scroll_outQueryString)
                )
                .addGroup(layout.createSequentialGroup()
                    .addGroup(layout.createParallelGroup()
                        .addComponent(self.lblParamList)
                        .addComponent(self.lblCount)
                    )
                    .addComponent(self.scroll_outParamList)
                )
            )
        )

        callbacks.addSuiteTab(self)

    def defineCheckBox(self, caption, selected=True, enabled=True):
        checkBox = JCheckBox(caption)
        checkBox.setSelected(selected)
        checkBox.setEnabled(enabled)
        return checkBox
    
    def saveConfig(self, e=None):
        config = {
            'saveFile': self.cbSaveFile.isSelected(),
            'paramUrl': self.cbParamUrl.isSelected(),
            'paramBody': self.cbParamBody.isSelected(),
            'paramMultiPart': self.cbParamMultiPart.isSelected(),
            'paramJson': self.cbParamJson.isSelected(),
            'paramCookie': self.cbParamCookie.isSelected(),
            'paramXml': self.cbParamXml.isSelected(),
            'paramXmklAttr': self.cbParamXmlAttr.isSelected(),
            'queryStringVal': self.inQueryStringVal.text,
            'showQueryString': self.cbShowQueryString.isSelected(),
            'includeCommonParams': self.cbIncludeCommonParams.isSelected(),
            'includePathWords': self.cbIncludePathWords.isSelected(),
            'paramJsonResponse': self.cbParamJSONResponse.isSelected(),
            'paramXmlResponse': self.cbParamXMLResponse.isSelected(),
            'paramInputField': self.cbParamInputField.isSelected(),
            'paramJSVars': self.cbParamJSVars.isSelected(),
            'paramMetaName': self.cbParamMetaName.isSelected()
            }
        self._callbacks.saveExtensionSetting("config", pickle.dumps(config))

    def restoreConfig(self, e=None):
        storedConfig = self._callbacks.loadExtensionSetting("config")
        if storedConfig != None:
            try:
                config = pickle.loads(storedConfig)
                self.cbSaveFile.setSelected(config['saveFile'])
                self.cbParamUrl.setSelected(config['paramUrl'])
                self.cbParamBody.setSelected(config['paramBody'])
                self.cbParamMultiPart.setSelected(config['paramMultiPart'])
                self.cbParamJson.setSelected(config['paramJson'])
                self.cbParamCookie.setSelected(config['paramCookie'])
                self.cbParamXml.setSelected(config['paramXml'])
                self.cbParamXmlAttr.setSelected(config['paramXmklAttr'])
                self.inQueryStringVal.text = config['queryStringVal'] 
                self.cbShowQueryString.setSelected(config['showQueryString']),
                self.cbIncludeCommonParams.setSelected(config['includeCommonParams']),
                self.cbIncludePathWords.setSelected(config['includePathWords']),
                self.cbParamJSONResponse.setSelected(config['paramJsonResponse']),
                self.cbParamXMLResponse.setSelected(config['paramXmlResponse']),
                self.cbParamInputField.setSelected(config['paramInputField']),
                self.cbParamJSVars.setSelected(config['paramJSVars']),
                self.cbParamMetaName.setSelected(config['paramMetaName'])
            except Exception as e:
                self._stderr.println(e)  
                pass
    
    def resetConfig(self, e=None):
        self.cbSaveFile.setSelected(True)
        self.cbParamUrl.setSelected(True)
        self.cbParamBody.setSelected(True)
        self.cbParamMultiPart.setSelected(True)
        self.cbParamJson.setSelected(False)
        self.cbParamJSONResponse.setSelected(False)
        self.cbParamXMLResponse.setSelected(False)
        self.cbParamInputField.setSelected(False)
        self.cbParamCookie.setSelected(False)
        self.cbParamXml.setSelected(False)
        self.cbParamXmlAttr.setSelected(False)
        self.cbShowQueryString.setSelected(True)
        self.inQueryStringVal.text = 'XNLV' 
        self.cbIncludeCommonParams.setSelected(True)
        self.cbIncludePathWords.setSelected(False)
        self.cbParamJSVars.setSelected(False)
        self.cbParamMetaName.setSelected(False)
        self.saveConfig

    def getTabCaption(self):
        return("Get All Params")

    def getUiComponent(self):
        return self.tab

    def createMenuItems(self, context):
        '''
        Invokes the "Get All Params" Menu.
        '''
        self.context = context
        if context.getInvocationContext() == context.CONTEXT_TARGET_SITE_MAP_TREE:
            menu_list = ArrayList()
            menu_item = JMenuItem("Get All Params", actionPerformed=self.menu_action)
            menu_list.add(menu_item)
            return menu_list

    def menu_action(self, event):
        
        # before starting the search, update the text boxes
        self.lblCount.text = '   SEARCHING...'
        self.outParamList.text = 'SEARCHING...'
        if self.cbShowQueryString.isSelected() == True:
            self.outQueryString.text = 'SEARCHING...'
    
        # Run everything in a thread so it doesn't freeze Burp while it gets everythng
        t = threading.Thread(target=self.do_everything, args=[])
        t.daemon = True
        t.start()
                
        return
    
    def do_everything (self):
        '''
        Obtains the selected messages from the interface. Filters the sitmap for all messages containing
        URLs within the selected messages' hierarchy. If so, the message is analyzed to create a parameter list.
        '''
        # Initialize
        self.roots.clear()
        if self.cbIncludeCommonParams.isSelected() == True:
            self.param_list = set(COMMON_PARAMS)
        else:
            self.param_list = set()

        # get all first-level selected messages and store the URLs as roots to filter the sitemap
        http_messages = self.context.getSelectedMessages()
        for http_message in http_messages:
            root = http_message.getUrl().toString()
            self.roots.add(root)
        
        # e.g. the root will be in the format protocol://domain:port/
        # get all sitemap entries associated with the selected messages and scrape them for parameters
        for http_message in self._callbacks.getSiteMap(None):
                        
            url = http_message.getUrl().toString()

            for root in self.roots:

                # will scrape the same URL multiple times if the site map has stored multiple instances
                # the site map stores multiple instances if it detects differences, so this is desirable
                rooturl = urlparse(root)
                responseurl = urlparse(url)

                if rooturl.hostname == responseurl.hostname:
                    # only scrape if there is a request to scrape
                    http_request = http_message.getRequest()
                    if http_request:
                        self.get_params(url, http_request)
                
                    # Get path words if requested
                    if self.cbIncludePathWords.isSelected():
                        self.get_path_words(responseurl)

                    # Get the response parameters if requested
                    if self.cbParamJSONResponse.isSelected() or self.cbParamXMLResponse.isSelected() or self.cbParamInputField.isSelected() or self.cbParamJSVars.isSelected() or self.cbParamMetaName.isSelected():
                        http_response = http_message.getResponse()
                        if http_response:
                            self.get_response_params(http_response)

        # Get the full path of the file
        filepath = self.get_filepath(root)
        
        # Display the parameters wherever the extension was configured     
        self.display_params(filepath)
        
        # Write the parameters to a file if required
        if self.cbSaveFile.isSelected():
            self.writefile_params(filepath)

    def get_params(self, url, http_request):
        '''
        Get all the parameters and add them to the param_list set.
        '''
        request = self._helpers.analyzeRequest(http_request)
        parameters = request.getParameters()[0:]
       
        for param in parameters:
            # If the paramater is of the type we want to log then get them
            if (param.getType() == PARAM_URL and self.cbParamUrl.isSelected()) or (param.getType() == PARAM_BODY and self.cbParamBody.isSelected()) or (param.getType() == PARAM_MULTIPART_ATTR and self.cbParamMultiPart.isSelected()) or (param.getType() == PARAM_JSON and self.cbParamJson.isSelected()) or (param.getType() == PARAM_COOKIE and self.cbParamCookie.isSelected()) or (param.getType() == PARAM_XML and self.cbParamXml.isSelected()) or (param.getType() == PARAM_XML_ATTR and self.cbParamXmlAttr.isSelected()):
                self.param_list.add(param.getName().strip())

        return

    def get_filepath(self, rootname):
        '''
        Determine the full path of the output file
        '''
        # Use the target domain in the filename
        filename = urlparse(rootname).hostname
        filename = filename + '_getAllParams.txt'
        
        # If on Windows then change the file path to the users Documents directory
        # otherwise it will just be in the users home directory
        try:
            if str(platform.uname()).find('Windows'):
                filepath = '~\\Documents\\' + filename
            else:
                filepath = '~/' + filename
        except:
            # If platform.uname() is not available, just default to '~/'
            filepath = '~/' + filename
            
        return filepath
        
    def display_params(self, filepath):
        '''
        Displays the parameter list to whatever Burp is configured for stdout.
        '''
        print('#')
        print('# Get All Params by /XNL-h4ck3r ')
        if self.cbSaveFile.isSelected():
            print('# The list of paramaters will be written to your home directory. ')
            print('# File path is: ' + filepath)
        print('#')
        
        # List all the parameters, one per line
        print('')
        print('# Below is the list of all the unique parameters')
        print('')
        index = 1
        allParams = ''
        self.outParamList.text = ''
        self.lblCount.text = '   UPDATING...   PLEASE WAIT...'
        if self.cbShowQueryString.isSelected() == True:
            self.outQueryString.text = 'UPDATING...'
        for param in sorted(self.param_list):
            try:
                if len(param) > 0:
                    print(param)
                    self.outParamList.text = self.outParamList.text + param + '\n'
                    # Build a list of paramaters in a concatenated string with unique values
                    allParams = allParams + param + '=' + self.inQueryStringVal.text + str(index) + '&'
                    index += 1
            except Exception as e: 
                self._stderr.println(e)   
        self.lblCount.text = '   ' + str(index) + ' POTENTIAL PARAMETERS FOUND'
         
        # List the paramaters in a concatenated string with unique values if required
        self.outQueryString.text = ''
        if self.cbShowQueryString.isSelected():
            print('')
            print('')
            print('# Or cut and paste the parameter string below to pass all parameters with value "' + self.inQueryStringVal.text + '?" where ? is a unique number.')
            print('# Then search for reflection of the word "' + self.inQueryStringVal.text + '"')
            print('')
            print(allParams)
            self.outQueryString.text = allParams

        # If no parameters were found, write that in the text box
        if self.outParamList.text == '':
            self.outParamList.text = 'NO PARAMETERS FOUND'
            if self.cbShowQueryString.isSelected() == True:
                self.outQueryString.text = 'NO PARAMETERS FOUND'
                  
        return
        
    def writefile_params(self, filepath):
        '''
        Writes the parameters to a file in users home directory
        '''
        # Write all parameters to a file if any exist
        if self.outParamList.text != 'NO PARAMETERS FOUND':
            with open(os.path.expanduser(filepath), 'w') as f:
                for param in sorted(self.param_list):
                    try:
                        f.write(param +'\n')
                    except Exception as e:
                        self._stderr.println(e)     
            return

    def get_response_params(self, http_response):
        '''
        Get XML and JSON responses, extract keys and add them to the param_list
        Original contributer: Pichik

        In addition it will extract name and id from <input> fields in HTML
        '''
        response = self._helpers.analyzeResponse(http_response)
        body_offset = response.getBodyOffset()
        response_string = self._helpers.bytesToString(http_response)
        body = response_string[body_offset:]

        if response.getStatedMimeType() == 'JSON':
            if self.cbParamJSONResponse.isSelected():
                try:
                    # Get only keys from json (everything between double quotes:)
                    json_keys = (re.findall('"([a-zA-Z0-9$_\.-]*?)":', body))
                    for key in json_keys:
                        self.param_list.add(key.strip())
                except Exception as e:
                    self._stderr.println(e)  

        elif response.getStatedMimeType() == 'XML':
            if self.cbParamXMLResponse.isSelected():
                try:
                    # Get XML attributes
                    xml_keys = (re.findall('<([a-zA-Z0-9$_\.-]*?)>', body))
                    for key in xml_keys:
                        self.param_list.add(key.strip())
                except Exception as e:
                    self._stderr.println(e)  

        elif response.getStatedMimeType() == 'HTML':
            if self.cbParamInputField.isSelected():
                # Get Input field name and id attributes
                try:
                    html_keys = (re.findall('<input(.*?)>', body))
                    for key in html_keys:
                        input_name = re.search(r"(?<=name=(\"|'))(.*?)(?=(\"|'))", key)
                        if input_name is not None and input_name.group() != "":
                            self.param_list.add(input_name.group().strip())
                        input_id = re.search(r"(?<=id=(\"|'))(.*?)(?=(\"|'))", key)
                        if input_id is not None and input_id.group() != "":
                            self.param_list.add(input_id.group().strip())
                except Exception as e:
                    self._stderr.println(e)  

            if self.cbParamJSVars.isSelected():
                # Get inline javascript variables defined with "let"
                try:
                    js_keys = re.finditer(r"(?<=let[\s])[\s]*[a-zA-Z$_][a-zA-Z0-9$_]*[\s]*(?=(\=|;|\n|\r))", body)
                    for key in js_keys:
                        if key is not None and key.group() != "":
                            self.param_list.add(key.group().strip())
                except Exception as e:
                    self._stderr.println(e)  
                # Get inline javascript variables defined with "var"
                try:
                    js_keys = re.finditer(r"(?<=var\s)[\s]*[a-zA-Z$_][a-zA-Z0-9$_]*?(?=(\s|=|,|;|\n))", body)
                    for key in js_keys:
                        if key is not None and key.group() != "":
                            self.param_list.add(key.group().strip())
                except Exception as e:
                    self._stderr.println(e)  
                # Get inline javascript constants
                try:
                    js_keys = re.finditer(r"(?<=const\s)[\s]*[a-zA-Z$_][a-zA-Z0-9$_]*?(?=(\s|=|,|;|\n))", body)
                    for key in js_keys:
                        if key is not None and key.group() != "":
                            self.param_list.add(key.group().strip())
                except Exception as e:
                    self._stderr.println(e) 

            if self.cbParamMetaName.isSelected():
                # Get meta tag name attribute
                try:
                    meta_keys = (re.findall('<meta(.*?)>', body))
                    for key in meta_keys:
                        meta_name = re.search(r"(?<=name=(\"|'))(.*?)(?=(\"|'))", key)
                        if meta_name is not None and meta_name.group() != "":
                            self.param_list.add(meta_name.group().strip())
                except Exception as e:
                    self._stderr.println(e) 
        
        elif response.getStatedMimeType() == 'script':
            if self.cbParamJSVars.isSelected():
                # Get javascript variables
                try:
                    js_keys = re.finditer(r"(?<=(var|let)\s)[\s]*[a-zA-Z$_][a-zA-Z0-9$_]*?(?=(\s|=|,|;|\n))", body)
                    for key in js_keys:
                        if key is not None and key.group() != "":
                            self.param_list.add(key.group().strip())
                except Exception as e:
                    self._stderr.println(e)  
                # Get javascript constants
                try:
                    js_keys = re.finditer(r"(?<=const\s)[\s]*[a-zA-Z$_][a-zA-Z0-9$_]*?(?=(\s|=|,|;|\n))", body)
                    for key in js_keys:
                        if key is not None and key.group() != "":
                            self.param_list.add(key.group().strip())
                except Exception as e:
                    self._stderr.println(e) 

        return

    def get_path_words(self, url):
        '''
        Get all words from path and if they do not contain file extension add them to the param_list
        Original contributer: Pichik
        '''
        # Split the URL on /
        words = re.compile(r'[\:/?=\-&]+',re.UNICODE).split(url.path)
        # Add the word to the parameter list, unless it has a . in it or is a number
        for word in words:
            if ("." not in word) and (not word.isnumeric()):
                self.param_list.add(word.strip())
        return