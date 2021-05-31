'''
Get All Params by /XNL-h4ck3r (@xnl_h4ck3r)

This is a python extension that runs in Portswigger's Burp Suite and parses an already crawled sitemap to build a custom parameter list. 
It also adds common parameter names that could be useful in the final list used for fuzzing.

Although it has a different function, the code was based on the why-cewler.py extension by Ianmaster53
(https://gist.github.com/lanmaster53/a0d3523279f3d1efdfe6d9dfc4da0d4a) just as a base template.

Usage:
1. Point Burp Suite to Jython in the Extender > Options tab.
2. Install this extension manually in the Extender > Extensions tab.
3. Select an option for extension output (File, Console or UI).
4. Right-click on any element in the Target tab's hierarchical sitemap.
5. Select the Extensions > Get All Params context menu item.

It is advised you keep Output as "Show in UI"
A file of all paramaters will be created in the users home directory (or Documnets for Windows) with the name "{TARGET}_getAllParams.txt"
The extension Output tab will show a combined string of all parameters and a test value of XNLV? (where ? is a unique number)
This string can be used in requests and then Burp history searched for any relection of XNLV

The following types of paramters with in the Burp IParamater interface will be retunred:
PARAM_URL (0) - Used to indicate a parameter within the URL query string.
PARAM_BODY (1) - Used to indicate a parameter within the message body.
PARAM_MULTIPART_ATTR (5) - Used to indicate the value of a parameter attribute within a multi-part message body (such as the name of an uploaded file).

The following type of parameters in Burp IParameter interface will NOT be returned:
PARAM_COOKIE (2) - Used to indicate an HTTP cookie.
PARAM_XML (3) - Used to indicate an item of data within an XML structure.
PARAM_XML_ATTR (4) - Used to indicate the value of a tag attribute within an XML structure.
PARAM_JSON (6) - Used to indicate an item of data within a JSON structure.

'''

from burp import IBurpExtender
from burp import IContextMenuFactory
from javax.swing import JMenuItem
from java.util import ArrayList, List
from HTMLParser import HTMLParser
from datetime import datetime
from urlparse import urlparse 
import sys
import os
import platform
import re

COMMON_PARAMS = ['page', 'callback', 'next', 'prev', 'previous', 'ref', 'go', 'return', 'goto', 'r_url', 'returnurl', 'returnuri', 'location', 'locationurl', 'retunr_url', 'goTo', 'r_Url', 'r_URL', 'returnUrl', 'returnURL', 'returnUri', 'retunrURI', 'locationUrl', 'locationURL', 'return_Url', 'return_URL', 'site', 'debug', 'active', 'admin', 'id' ]

PARAM_URL = 0
PARAM_BODY = 1
PARAM_COOKIE = 2
PARAM_XML = 3
PARAM_XML_ATTR = 4
PARAM_MULTIPART_ATTR = 5
PARAM_JSON = 6

class BurpExtender(IBurpExtender, IContextMenuFactory):
    '''
    BurpExtender Class as per Reference API.
    '''

    def registerExtenderCallbacks(self, callbacks):
        '''
        Registers the extension and initializes the root URLs and parameter list sets.
        '''
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.context = None
        self.roots = set()
        self.param_list = set(COMMON_PARAMS)
        callbacks.setExtensionName("Get All Params")
        callbacks.registerContextMenuFactory(self)
        sys.stdout = callbacks.getStdout()
        return

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
        '''
        Obtains the selected messages from the interface. Filters the sitmap for all messages containing
        URLs within the selected messages' hierarchy. If so, the message is analyzed to create a parameter list.
        '''
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
        
        # Get the full path of the file
        filepath = self.get_filepath(root)
        
        # Display the parameters wherever the extension was configured     
        self.display_params(filepath)
        
        # Write the parameters to a file
        self.writefile_params(filepath)
        
        return
    
    def get_params(self, url, http_request):
        '''
        Get all the parameters and add them to the param_list set.
        '''
        request = self._helpers.analyzeRequest(http_request)
        parameters = request.getParameters()[1:]
       
        for param in parameters:
        
            # If the paramater is of the type we want to log then get them
            if param.getType() == PARAM_URL or param.getType() == PARAM_BODY or param.getType() == PARAM_MULTIPART_ATTR:
                self.param_list.add(param.getName())
            
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
        print('# The list of paramaters will be written to your home directory. ')
        print('# File path is: ' + filepath)
        print('#')
        
        # List all the parameters, one per line
        print('')
        print('# Below is the list of all the unique parameters')
        index = 1
        allParams = ''
        for param in sorted(self.param_list):
            try:
                print(param)
                # Build a list of paramaters in a concatenated string with unique values
                allParams = allParams + param + '=XNLV' + str(index) + '&'
            except: 
                pass   
            index += 1
        
        # List the paramaters in a concatenated string with unique values
        print('')
        print('# Or cut and paste the parameter string below to pass all parameters with value "XNLV?" where ? is a unique number.')
        print('# Then search for reflection of the word "XNLV"')
        print('')
        print(allParams)
          
        return
        
    def writefile_params(self, filepath):
        '''
        Writes the parameters to a file in users home directory
        '''
        # Write all parameters to a file
        with open(os.path.expanduser(filepath), 'w') as f:
            for param in sorted(self.param_list):
                try:
                    f.write(param +'\n')
                except:
                    pass
        return
