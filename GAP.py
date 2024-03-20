"""
GAP by /XNL-h4ck3r (@xnl_h4ck3r)

Respect and thanks go to @HolyBugx for help with the original versions ideas, testing and patience!
Also, thanks to so many people who have made suggestions, reported issues, and helped me test each version I release!

Get full instructions at https://github.com/xnl-h4ck3r/GAP-Burp-Extension/blob/main/GAP%20Help.md or press the Help button on the GAP tab

Good luck and good hunting! If you really love the tool (or any others), or they helped you find an awesome bounty, consider BUYING ME A COFFEE! (https://ko-fi.com/xnlh4ck3r) (I could use the caffeine!)
"""
VERSION="4.5"

_debug = False

from burp import IBurpExtender, IContextMenuFactory, IScopeChangeListener, ITab, IScanIssue
from javax.swing import (
    JFrame,
    JMenuItem,
    GroupLayout,
    JPanel,
    JCheckBox,
    JTextField,
    JLabel,
    JButton,
    JScrollPane,
    JTextArea,
    ScrollPaneConstants,
    JFileChooser,
    BorderFactory,
    JEditorPane,
    ImageIcon,
    JProgressBar
)
from java.util import ArrayList
from urlparse import urlparse
from java.io import PrintWriter, File
from java.awt import Color, Font, Image, Cursor, Desktop
from java.awt.event import KeyListener
from java.net import URL, URI
from java.lang import System
from javax.imageio import ImageIO

import os
import re
import pickle
import threading
import time
import urllib
from datetime import datetime
from array import array
try:
    import profile
    import pstats
except:
    pass

WORDLIST_IMPORT_ERROR = ""
try:
    import warnings
    from bs4 import BeautifulSoup, Comment
    warnings.filterwarnings("ignore", category=UserWarning, module='bs4')
except Exception as e:
    if str(e).startswith("No module named"):
        WORDLIST_IMPORT_ERROR = "The following installation instructions NEED TO BE FOLLOWED EXACTLY to be able to use Words mode (as mentioned in https://github.com/xnl-h4ck3r/GAP-Burp-Extension#installation). NOTE: Links and Parameters mode will still work without this.\n\n1. Visit https://www.jython.org/download, and download the latest stand alone JAR file, e.g. jython-standalone-2.7.3.jar.\n2. Open Burp, go to Extensions -> Extension Settings -> Python Environment, set the Location of Jython standalone JAR file and Folder for loading modules to the directory where the Jython JAR file was saved.\n3. On a command line, go to the directory where the jar file is and run \"java -jar jython-standalone-2.7.3.jar -m ensurepip\".\n4. Download the GAP.py and requirements.txt from this project and place in the same directory.\n5. Install Jython modules by running \"java -jar jython-standalone-2.7.3.jar -m pip install -r requirements.txt\".\n6. Go to the Extensions -> Installed and click Add under Burp Extensions.\n7. Select Extension type of Python and select the GAP.py file (this file can be placed in any directory)."
    else:
        WORDLIST_IMPORT_ERROR = "The following error occurred when importing beauttifulsoup4: " + str(e) + "\nPlease make sure you have followed the installation instructions on https://github.com/xnl-h4ck3r/GAP-Burp-Extension#installation\n"
        print("WARNING: Could not import beauttifulsoup4 for word mode: " + str(e))
    
# Try to import html5lib as a parser for beautifulsoup4 because it's more accurate than the default html.parser
try:
    html5libInstalled = True
    import html5lib
except Exception as e:
    html5libInstalled = False

# Sus Parameters from @jhaddix and @G0LDEN_infosec
SUS_CMDI = ['execute','dir','daemon','cli','log','cmd','download','ip','upload']
SUS_DEBUG = ['test','reset','config','shell','admin','exec','load','cfg','dbg','edit','root','create','access','disable','alter','make','grant','adm','toggle','execute','clone','delete','enable','rename','debug','modify']
SUS_FILEINC =  ['root','directory','path','style','folder','default-language','url','platform','textdomain','document','template','pg','php_path','doc','type','lang','token','name','pdf','file','etc','api','app','resource-type']
SUS_IDOR = ['count','key','user','id','extended_data','uid2','group','team_id','data-id','no','username','email','account','doc','uuid','profile','number','user_id','edit','report','order']
SUS_OPENREDIRECT = ['u','redirect_uri','failed','r','referer','return_url','redirect_url','prejoin_data','continue','redir','return_to','origin','redirect_to','next']
SUS_SQLI = ['process','string','id','referer','password','pwd','field','view','sleep','column','log','token','sel','select','sort','from','search','update','pub_group_id','row','results','role','table','multi_layer_map_list','order','filter','params','user','fetch','limit','keyword','email','query','c','name','where','number','phone_number','delete','report']
SUS_SSRF = ['sector_identifier_uri', 'request_uris', 'logo_uri', 'jwks_uri', 'start','path','domain','source','url','site','view','template','page','show','val','dest','metadata','out','feed','navigation','image_host','uri','next','continue','host','window','dir','reference','filename','html','to','return','open','port','stop','validate','resturl','callback','name','data','ip','redirect']
SUS_SSTI = ['preview','activity','id','name','content','view','template','redirect']
SUS_XSS = ['path','admin','class','atb','redirect_uri','other','utm_source','currency','dir','title','endpoint','return_url','users','cookie','state','callback','militarybranch','e','referer','password','author','body','status','utm_campaign','value','text','search','flaw','vote','pathname','params','user','t','utm_medium','q','email','what','file','data-original','description','subject','action','u','nickname','color','language_id','auth','samlresponse','return','readyfunction','where','tags','cvo_sid1','target','format','back','term','r','id','url','view','username','sequel','type','city','src','p','label','ctx','style','html','ad_type','s','issues','query','c','shop','redirect']

# Additional Sus Parameters
SUS_MASSASSIGNMENT = ['user','profile','role','settings','data','attributes','post','comment','order','product','form_fields','request']
             
# A comma separated list of Link exclusions used when no options have been saved, or when the "Restore defaults" button is pressed
# Links are NOT displayed if they contain these strings. This just applies to the links found in endpoints, not the origin link in which it was found
DEFAULT_EXCLUSIONS = ".css,.jpg,.jpeg,.png,.svg,.img,.gif,.mp4,.flv,.ogv,.webm,.webp,.mov,.mp3,.m4a,.m4p,.scss,.tif,.tiff,.ttf,.otf,.woff,.woff2,.bmp,.ico,.eot,.htc,.rtf,.swf,.image,w3.org,doubleclick.net,youtube.com,.vue,jquery,bootstrap,font,jsdelivr.net,vimeo.com,pinterest.com,facebook,linkedin,twitter,instagram,google,mozilla.org,jibe.com,schema.org,schemas.microsoft.com,wordpress.org,w.org,wix.com,parastorage.com,whatwg.org,polyfill,typekit.net,schemas.openxmlformats.org,openweathermap.org,openoffice.org,reactjs.org,angularjs.org,java.com,purl.org,/image,/img,/css,/wp-json,/wp-content,/wp-includes,/theme,/audio,/captcha,/font,node_modules,.wav,.gltf,.pict,.svgz,.eps,.midi,.mid,.avif,.jfi,.jfif,.jfif-tbnl,.jif,.jpe,.pjpg"

# A comma separated list of Content-Type exclusions used to determine what requests are checked for potential links
# These content types will NOT be checked
CONTENTTYPE_EXCLUSIONS = "text/css,image/jpeg,image/jpg,image/png,image/svg+xml,image/gif,image/tiff,image/webp,image/bmp,image/x-icon,image/vnd.microsoft.icon,font/ttf,font/woff,font/woff2,font/x-woff2,font/x-woff,font/otf,audio/mpeg,audio/wav,audio/webm,audio/aac,audio/ogg,audio/wav,audio/webm,video/mp4,video/mpeg,video/webm,video/ogg,video/mp2t,video/webm,video/x-msvideo,application/font-woff,application/font-woff2,application/vnd.android.package-archive,binary/octet-stream,application/octet-stream,application/pdf,application/x-font-ttf,application/x-font-otf,application/x-font-woff,application/vnd.ms-fontobject,image/avif,application/zip,application/x-zip-compressed,application/x-msdownload,application/x-apple-diskimage,application/x-rpm,application/vnd.debian.binary-package,application/x-font-truetype,font/opentype,image/pjpeg,application/x-troff-man,application/font-otf,application/x-ms-application,application/x-msdownload,video/x-ms-wmv,image/x-png,video/quicktime,image/x-ms-bmp,font/opentype,application/x-font-opentype,application/x-woff,audio/aiff,image/jp2,video/x-m4v"

# A comma separated list of file extension exclusions used when the content-type isn't available. Files with these extensions will NOT be checked
FILEEXT_EXCLUSIONS = ".zip,.dmg,.rpm,.deb,.gz,.tar,.jpg,.jpeg,.png,.svg,.img,.gif,.mp4,.flv,.ogv,.webm,.webp,.mov,.mp3,.m4a,.m4p,.scss,.tif,.tiff,.ttf,.otf,.woff,.woff2,.bmp,.ico,.eot,.htc,.rtf,.swf,.image,.wav,.gltf,.pict,.svgz,.eps,.midi,.mid,.pdf,.jfi,.jfif,.jfif-tbnl,.jif,.jpe,.pjpg"

# The default value (used until options are saved, or when the "Restore defaults" button is pressed) for the generated query string of all parameters.
DEFAULT_QSV = "XNLV"

# A list of files used in the Link Finding Regex. These are used in the 5th capturing group that aren't obvious links, but could be files
LINK_REGEX_FILES = "php|php3|php5|asp|aspx|ashx|cfm|cgi|pl|jsp|jspx|json|js|action|html|xhtml|htm|bak|do|txt|wsdl|wadl|xml|xls|xlsx|bin|conf|config|bz2|bzip2|gzip|tar\.gz|tgz|log|src|zip|js\.map"

# Default content types where to look for Words
DEFAULT_WORDS_CONTENT_TYPES = "text/html,application/xml,application/json,text/plain,application/xhtml+xml,application/ld+json,text/xml"

# Default english "stop word" list
DEFAULT_STOP_WORDS = "a,aboard,about,above,across,after,afterwards,again,against,all,almost,alone,along,already,also,although,always,am,amid,among,amongst,an,and,another,any,anyhow,anyone,anything,anyway,anywhere,are,around,as,at,back,be,became,because,become,becomes,becoming,been,before,beforehand,behind,being,below,beneath,beside,besides,between,beyond,both,bottom,but,by,can,cannot,cant,con,concerning,considering,could,couldnt,cry,de,describe,despite,do,done,down,due,during,each,eg,eight,either,eleven,else,elsewhere,empty,enough,etc,even,ever,every,everyone,everything,everywhere,except,few,fifteen,fifty,fill,find,fire,first,five,for,former,formerly,forty,found,four,from,full,further,get,give,go,had,has,hasnt,have,he,hence,her,here,hereafter,hereby,herein,hereupon,hers,herself,him,himself,his,how,however,hundred,i,ie,if,in,inc,indeed,inside,interest,into,is,it,its,itself,keep,last,latter,latterly,least,less,like,ltd,made,many,may,me,meanwhile,might,mill,mine,more,moreover,most,mostly,move,much,must,my,myself,name,namely,near,neither,never,nevertheless,next,nine,no,nobody,none,noone,nor,not,nothing,now,nowhere,of,off,often,on,once,one,only,onto,or,other,others,otherwise,our,ours,ourselves,out,outside,over,own,part,past,per,perhaps,please,put,rather,re,regarding,round,same,see,seem,seemed,seeming,seems,serious,several,she,should,show,side,since,sincere,six,sixty,so,some,somehow,someone,something,sometime,sometimes,somewhere,still,such,take,ten,than,that,the,their,them,themselves,then,thence,there,thereafter,thereby,therefore,therein,thereupon,these,they,thick,thin,third,this,those,though,three,through,throughout,thru,thus,to,together,too,top,toward,towards,twelve,twenty,two,un,under,underneath,until,unto,up,upon,us,very,via,want,was,wasnt,we,well,went,were,weve,what,whatever,when,whence,whenever,where,whereafter,whereas,whereby,wherein,whereupon,wherever,whether,which,while,whilst,whither,whoever,whole,whom,whose,why,will,with,within,without,would,yet,you,youll,your,youre,yours,yourself,yourselves,youve"

# The GAP Help file and 404 message if unavailable
GAP_HELP_URL = "https://github.com/xnl-h4ck3r/GAP-Burp-Extension/blob/main/GAP%20Help.md"
GAP_HELP_URL_BUTTON = (
    "https://raw.githubusercontent.com/xnl-h4ck3r/GAP-Burp-Extension/main/GAP%20Help.md"
)
GAP_HELP_404 = (
    "<h1>Oops... mind the GAP!</h1><p>Sorry, this should be displaying the content of the following page:<p><a href="
    + GAP_HELP_URL
    + ">"
    + GAP_HELP_URL
    + "</a><p>However, there seems to be a problem connecting to that resource.<p>Please try again later. If the problem persists, please raise an issue on Github."
)

# URLs for icons used
HELP_ICON = (
    "https://cdn0.iconfinder.com/data/icons/simply-orange-1/128/questionssvg-512.png"
)
DIR_ICON = "https://cdn0.iconfinder.com/data/icons/simply-orange-1/128/currency_copysvg-512.png"

# Enumeration of request parameter types identified by Burp
PARAM_URL = 0
PARAM_BODY = 1
PARAM_COOKIE = 2
PARAM_XML = 3
PARAM_XML_ATTR = 4
PARAM_MULTIPART_ATTR = 5
PARAM_JSON = 6

# The default maximum length of words to add
DEFAULT_MAX_WORD_LEN = "40"

# The default value for Link Prefix
DEFAULT_LINK_PREFIX = "https://www.CHANGE.THIS"

# Get the GAP logo from the Github page
URL_GAP_LOGO = "https://github.com/xnl-h4ck3r/GAP-Burp-Extension/raw/main/GAP/images/banner.png"

# KoFi links for buying me a coffee
URL_KOFI = "https://ko-fi.com/B0B3CZKR5"
URL_KOFI_BUTTON = "https://storage.ko-fi.com/cdn/kofi2.png?v=3"

# My Github URL
URL_GITHUB = "https://github.com/xnl-h4ck3r"

# Set the colour for Burp Orange
COLOR_BURP_ORANGE = Color(0xE36B1E)
        
class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):
    def registerExtenderCallbacks(self, callbacks):
        """
        Registers the extension and initializes
        """
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        self.context = None
        self.isBurpCommunity = False # We will assume False until we try to create an Issue
        self.roots = set()
        self.currentReqResp = None # Object to hold the current request/response being processed
        self.currentContentTypeInclude = False
        self.allScopePrefixes = set()
        self.param_list = set()
        self.paramUrl_list = set()
        self.paramSus_list = set()
        self.paramSusUrl_list = set()
        self.susParamText = set()
        self.susParamIssue = set()
        self.raisedIssues = set()
        self.txtParamQuery = ""
        self.txtParamQuerySus = ""
        self.countParam = 0
        self.countParamUnique = 0
        self.countParamSus = 0
        self.countParamSusUnique = 0
        self.link_list = set()
        self.linkInScope_list = set()
        self.linkUrl_list = set()
        self.linkUrlInScope_list = set()
        self.countLinkUnique = 0
        self.word_list = set()
        self.wordUrl_list = set()
        self.countWordUnique = 0
        self.lstStopWords = {}
        callbacks.setExtensionName("GAP")
        callbacks.registerContextMenuFactory(self)
        callbacks.registerScopeChangeListener(self.scopeChanged)
        self.dictCheckedLinks = {}
        self.flagCANCEL = False
        self.parentTabbedPane = None
        self.tabDefaultColor = None
        self.linkPrefixColor = None
        
        # Take the LINK_REGEX_FILES values and build a string of any values over 4 characters or has a number in it
        # This is used in the 4th capturing group Link Finding regex
        lstFileExt = LINK_REGEX_FILES.split("|")
        self.LINK_REGEX_NONSTANDARD_FILES = ""
        for ext in lstFileExt:
            if len(ext) > 4 or any(chr.isdigit() for chr in ext):
                if self.LINK_REGEX_NONSTANDARD_FILES == "":
                    self.LINK_REGEX_NONSTANDARD_FILES = ext
                else:
                    self.LINK_REGEX_NONSTANDARD_FILES = (
                        self.LINK_REGEX_NONSTANDARD_FILES + "|" + ext
                    )

        # Compile the link regex
        self.REGEX_LINKS = re.compile(r"(?:^|\"|'|\\n|\\r|\n|\r|\s)(((?:[a-zA-Z]{1,10}:\/\/|\/\/)([^\"'\/\s]{1,255}\.[a-zA-Z]{2,24}|localhost)[^\"'\n\s]{0,255})|((?:\/|\.\.\/|\.\/)[^\"'><,;| *()(%%$^\/\\\[\]][^\"'><,;|()\s]{1,255})|([a-zA-Z0-9_\-\/]{1,}\/[a-zA-Z0-9_\-\/]{1,255}\.(?:[a-zA-Z]{1,4}" + self.LINK_REGEX_NONSTANDARD_FILES + ")(?:[\?|\/][^\"|']{0,}|))|([a-zA-Z0-9_\-]{1,255}\.(?:" + LINK_REGEX_FILES + ")(?:\?[^\"|^']{0,255}|)))(?:\"|'|\\n|\\r|\n|\r|\s|$)|(?<=^Disallow:\s)[^\$\n]*|(?<=^Allow:\s)[^\$\n]*|(?<= Domain\=)[^\";']*|(?<=\<)https?:\/\/[^>\n]*|(\"|\')([A-Za-z0-9_-]+\/)+[A-Za-z0-9_-]+(\.[A-Za-z0-9]{2,}|\/?(\?|\#)[A-Za-z0-9_\-&=\[\]]*)(\"|\')", re.IGNORECASE)
        
        # Regex for checking Burp url when checking if in scope
        self.REGEX_BURPURL = re.compile(r"^(https?:)?\/\/([-a-zA-Z0-9_]+\.)?[-a-zA-Z0-9_]+\.[-a-zA-Z0-9_\.\?\#\&\=]+$", re.IGNORECASE)
        
        # Regex for JSON keys
        self.REGEX_JSONKEYS = re.compile(r'"([a-zA-Z0-9$_\.-]*?)":')
        
        # Regex for XML attributes
        self.REGEX_XMLATTR = re.compile(r"<([a-zA-Z0-9$_\.-]*?)>")
        
        # Regex for HTML input fields
        self.REGEX_HTMLINP = re.compile(r"<input(.*?)>", re.IGNORECASE)
        self.REGEX_HTMLINP_NAME = re.compile(r"(?<=\sname)[\s]*\=[\s]*(\"|')(.*?)(?=(\"|\'))", re.IGNORECASE)    
        self.REGEX_HTMLINP_ID = re.compile(r"(?<=\sid)[\s]*\=[\s]*(\"|')(.*?)(?=(\"|'))", re.IGNORECASE)
    
        # Regex for Sourcemap
        self.REGEX_SOURCEMAP = re.compile(r"(?<=SourceMap\:\s).*?(?=\n)", re.IGNORECASE)
        
        # Regex for Potential Words
        self.REGEX_WORDS = re.compile(r"(?<![\/])\b\w{3,}\b(?![\/])")
        self.REGEX_WORDSUB = re.compile(r'\"|%22|<|%3c|>|%3e|\(|%28|\)|%29|\s|%20', re.IGNORECASE)
        
        # Regex for standard port
        self.REGEX_PORT80 = re.compile(r":80[^0-9]")
        self.REGEX_PORT443 = re.compile(r":443[^0-9]")
        self.REGEX_PORTSUB = re.compile(r":80[^0-9]|:443[^0-9]")
        self.REGEX_PORTSUB80 = re.compile(r":80")
        self.REGEX_PORTSUB443 = re.compile(r":443")
        
        # Regex for valid parameter
        self.REGEX_PARAM = re.compile(r"[0-9a-zA-Z_]")
        
        # Regex for param keys
        self.REGEX_PARAMKEYS = re.compile(r"(?<=\?|&)[^\=\&\n].*?(?=\=|&|\n)")
        
        # Regex for parameters
        self.REGEX_PARAMSPOSSIBLE = re.compile(r"(?<=[^\&|%26|\&amp;|\&#0?38;|\u0026|\\u0026|\\\\u0026|\\x26|\x26])(\?|%3f|\&#0?63;|\u003f|\\u003f|\\\\u003f|\&|%26|\&amp;|\&#0?38;|\u0026|\\u0026|\\\\u0026|\\x26|%3d|\&#0?61;|\u003d|\\u003d|\\\\u003d|\\x3d|\&quot;|\&#0?34;|\u0022|\\u0022|\\\\u0022|\&#0?39;)[a-z0-9_\-]{3,}(\=|%3d|\&#0?61;|\u003d|\\u003d|\\\\u003d|\x3d|\\x3d)(?=[^\=|%3d|\&#0?61;|\u003d|\\u003d|\\\\u003d|\x3d|\\x3d])", re.IGNORECASE)
        self.REGEX_PARAMSSUB = re.compile(r"\?|%3f|\&#0?63;|\u003f|\\u003f|\\\\u003f|\=|%3d|\&#0?61;|\u003d|\\u003d|\\\\u003d|\\x3d|\x3d|%26|\&amp;|\&#0?38;|\u0026|\\u0026|\\\\u0026|\\x26|\x26|\&quot;|\&#0?34;|\u0022|\\u0022|\\\\u0022|\\x22|\x22|\&#0?39;", re.IGNORECASE)
        self.REGEX_JSLET = re.compile(r"(?<=let[\s])[\s]*[a-zA-Z$_][a-zA-Z0-9$_]*[\s]*(?=(\=|;|\n|\r))")
        self.REGEX_JSVAR = re.compile(r"(?<=var\s)[\s]*[a-zA-Z$_][a-zA-Z0-9$_]*?(?=(\s|=|,|;|\n))")
        self.REGEX_JSCONSTS = re.compile(r"(?<=const\s)[\s]*[a-zA-Z$_][a-zA-Z0-9$_]*?(?=(\s|=|,|;|\n))")
        
        # Regex for Request parameters
        self.REGEX_PARAMSJSON = re.compile(r"{\"[^\}]+}")
        self.REGEX_PARAMSJSONPARAMS = re.compile(r"(?<=\")[^\"\:]+(?=\":)")
        
        # Regex for links
        self.REGEX_LINKSSLASH = re.compile(r"(\&#x2f;|\&#0?2f|%2f|\u002f|\\u002f|\\/)", re.IGNORECASE)
        self.REGEX_LINKSCOLON = re.compile(r"(\&#x3a;|\&#0?3a|%3a|\u003a|\\u003a)", re.IGNORECASE)
        self.REGEX_LINKSAND = re.compile(r"%26|\&amp;|\&#0?38;|\u0026|u0026|x26|\x26", re.IGNORECASE)
        self.REGEX_LINKSEQUAL = re.compile(r"%3d|\&equals;|\&#0?61;|\u003d|u003d|x3d|\x3d", re.IGNORECASE)
        self.REGEX_LINKBRACKET = re.compile(r"\(.*\)")
        self.REGEX_LINKBRACES = re.compile(r"\{.*\}")
        self.REGEX_LINKSEARCH1 = re.compile(r"^[^(]*\)+$")
        self.REGEX_LINKSEARCH2 = re.compile(r"^[^{}]*\}+$")
        self.REGEX_LINKSEARCH3 = re.compile(r"^[^\[]]*\]+$")
        self.REGEX_LINKSEARCH4 = re.compile(r"<\/")
        self.REGEX_VALIDHOST = re.compile(r"^([A-Za-z0-9_-]+\.)+[A-Za-z0-9_-]{2,}$")
        
        # Regex for sus params
        self.REGEX_SUSPARAM = re.compile("^[A-Za-z0-9_-]+$")
        
        # Make the Stop Word list and make all lower case
        try:
            self.lstStopWords = DEFAULT_STOP_WORDS.split(",")
            self.lstStopWords = list(map(str.lower,self.lstStopWords))
        except Exception as e:
            self._stderr.println("registerExtenderCallbacks 1")
            self._stderr.println(e)

                
        # Create the UI part of GAP
        self._createUI()
              
        # Display welcome message
        print("GAP - Version " + VERSION)
        print("by @xnl_h4ck3r\n")
        print(
            "The full Help documentation can be found at "
            + GAP_HELP_URL
            + " or from the Help icon on the GAP tab\n"
        )
        if _debug:
            print("DEBUG MODE ON\n")
        
        print("If you ever see anything in the Errors tab, please raise an issue on Github so I can fix it!")
        print("Want to buy me a coffee?! - " + URL_KOFI + "\n")
        
        try:
            if not html5libInstalled:
                print("WARNING: Could not import html5lib for more accurate parsing of words by beatifulsoup4 library.")
        except:
            pass
    
    def setContextHelp(self, enable):
        if enable:
            self.lblRequestParams.setToolTipText("These are identified by Burp itself through the API IParameter interface.")
            self.cbParamUrl.setToolTipText("A parameter within the URL query string, identified by Burp itself.")
            self.cbParamBody.setToolTipText("A parameter within the request body, identified by Burp itself.")
            self.cbParamMultiPart.setToolTipText("The value of a parameter attribute within a multi-part message body (such as the name of an uploaded file), identified by Burp itself.")
            self.cbParamJson.setToolTipText("An item of data within a JSON structure, identified by Burp itself.")
            self.cbParamCookie.setToolTipText("An HTTP cookie name, identified by Burp itself.")
            self.cbParamXml.setToolTipText("Items of data in XML structure, identified by Burp itself.")
            self.cbParamXmlAttr.setToolTipText("Value of tag attributes in XML structure, identified by Burp itself.")
            self.lblResponseParams.setToolTipText("These are identified by GAP, mainly with regular expressions.")
            self.cbParamJSONResponse.setToolTipText("If the response has a MIME type of JSON then the Key names will be retrieved.")
            self.cbParamXMLResponse.setToolTipText("If the response has a MIME type of XML then the XML attributes are retrieved.")
            self.cbParamInputField.setToolTipText("If the response has a MIME type of HTML then the value of the NAME and ID attributes of any INPUT tags are retrieved.")
            self.cbParamJSVars.setToolTipText("Javascript variables set with 'var', 'let' or 'const' are retrieved.")
            self.cbParamFromLinks.setToolTipText("Any URL query string parameters in potential Links found will be retrieved, only if they are clearly in scope,\nor there is just a path and no way of determining if it is in scope.")
            self.cbReportSusParams.setToolTipText("If a 'sus' parameter is identified, a Burp custom Issue will be raised (unavailable in Burp Community Edition).\nThere will be no markers in the Request/Response of the Issue showing where the named parameter can be found because including this functionality\nseriously increases the time GAP can take to run, so this is not a feature at the moment.\nFor Burp Community Edition, the details of the parameter will be written to the extension output.")
            self.cbWordLower.setToolTipText("Any word found that contains an uppercase letter will also be added as an all lowercase word.")
            self.cbWordPlurals.setToolTipText("If checked, then for each word found, a suitable singular or plural version will also be added to the output.")
            self.cbWordPaths.setToolTipText("Any path words in selected links will be added as words.")
            self.cbWordParams.setToolTipText("If the Parameters Mode is enabled, all potential params will also be added to the word list.")
            self.cbWordComments.setToolTipText("If checked, all words within HTML comments will be considered.")
            self.cbWordImgAlt.setToolTipText("If checked, all words with the ALT attribute of IMG tags will be considered.")
            self.cbWordDigits.setToolTipText("If un-checked, then any words with numeric digits will be excluded from output.")
            self.lblWordsMaxLen.setToolTipText("The maximum length of words that will be output (this excludes plurals of minimum length words).\nThis can be a minimum of 3.")
            self.inWordsMaxlen.setToolTipText("The maximum length of words that will be output (this excludes plurals of minimum length words).\nThis can be a minimum of 3.")
            self.cbToolTips.setToolTipText("Turn contextual help on or off.")
            self.cbIncludePathWords.setToolTipText("The words in the response URL path are included as potential parameters if the URL is in scope.")
            self.cbSiteMapEndpoints.setToolTipText("This will include endpoints from the Burp Site map (what was selected) in the potential Link list, if they are in scope.")
            self.cbRelativeLinks.setToolTipText("If checked, links found that start with ./ or ../ will be included in the results.")
            self.cbLinkPrefix.setToolTipText("If checked, the value(s) in the text field will be prefixed to any links found that do not have a domain, e.g. /api/user/1.\nMultiple domains can be provided, separated by a semicolon, e.g. http://example.com;https://sub.example.com")
            self.inLinkPrefix.setToolTipText("You can provide multiple links by separating with a semicolon, e.g. https://example.com;https://example.co.uk")
            self.cbLinkPrefixScope.setToolTipText("If checked, the root of each target selected in the Site Map will be prefixed to any links found that do not have a domain, e.g. /api/user/1")
            self.cbUnPrefixed.setToolTipText("If the 'Prefix with selected target(s)' or 'Prefix with link(s)' option is checked then this option can be checked to include\nthe original un-prefixed link in addition to the prefixed link.")
            self.cbSaveFile.setToolTipText("If this option is checked then when GAP completes a run, a file will be created with the potential parameters, with potential links, and target specific wordlist.\nThese files will be created in the specified directory.\nIf the directory is invalid then the users home directory will be used.")
            self.inSaveDir.setToolTipText("The directory where a file will be created with the potential parameters, with potential links, and target specific wordlist.")
            self.btnChooseDir.setToolTipText("Choose the directory where output files will be saved.")
            self.cbShowSusParams.setToolTipText("If this feature is ticked, only potential parameters that are 'sus' are shown followed by the associated vulnerability type(s).")
            self.cbShowQueryString.setToolTipText("This checkbox can be used to switch between the list of parameters and a concatenated\nquery string with all parameters with a value given in the following text box.")
            self.inQueryStringVal.setToolTipText("This is a value that is used to create the concatenated query string, with each parameter given this value followed by a unique number of the parameter.\nThis query string can be used to manually append to a URL and check for reflections.")
            self.btnRestoreDefaults.setToolTipText("If for any reason you want to revert to the default configuration options, you can click this button.")
            self.btnSave.setToolTipText("Any changes made to the configuration settings of GAP can be saved for future use by clicking this button.")
            self.progBar.setToolTipText("What request is being processed out of the total number of requests for current target.")
            self.progStage.setToolTipText("What Site Map target is being processed out of the total number of targets selected.")
            self.cbShowParamOrigin.setToolTipText("If this is ticked, the potential parameter will be followed by the HTTP request endpoint (in square brackets) that the parameter was found in.\nA parameter could have been found in more than one request, so this view can show duplicate links, one per origin endpoint.")
            self.cbShowLinkOrigin.setToolTipText("If this feature is ticked, the potential link will be followed by the HTTP request endpoint (in square brackets) that the link was found in.\nA link could have been found in more than one request, so this view can show duplicate links, one per origin endpoint.")
            self.cbInScopeOnly.setToolTipText("If this feature is ticked, and the potential links contain a host, then this link will be checked against the Burp Target Scope.\nIf it is not in scope then the link will be removed from the output.\nNOTE: This does not take any Burp 'Exclude from scope' entries into account.\nAlso, if it is not possible to determine the scope (e.g. it may just be a path without a host) then it will be included as in scope to avoid omitting anything potentially useful.")
            self.lblLinkFilter.setToolTipText("Any value entered in the Filter input field followed by ENTER or pressing 'Apply filter' will determine which links will be displayed.\nThis can depend on the values of the other two options.")
            self.cbLinkFilterNeg.setToolTipText("If selected, any link containing the Filter text will NOT be displayed.\nIf unselected, then only links containing the filter will be displayed.")
            self.cbLinkCaseSens.setToolTipText("If selected, the value is the Filter input field will be case sensitive when determining which Links to display.")
            self.inLinkFilter.setToolTipText("Any value entered in the Filter input field followed by ENTER or pressing 'Apply filter' will determine which links will be displayed.\nThis can depend on the values of the other two options.")
            self.cbShowWordOrigin.setToolTipText("If this feature is ticked, the words will be followed by the HTTP request endpoint (in square brackets) that the word was found in.\nA word could have been found in more than one request, so this view can show duplicate links, one per origin endpoint.\nIf the word was generated by GAP (e.g. a plural or singular version) then it will be followed by [GAP] instead of an origin endpoint.")
            self.lblStopWords.setToolTipText("The term 'stop words' comes from Natural Language Processing where they are common words that will be excluded from content.\nIf a word exists in this list before running, then it will be excluded from output.")
            self.inStopWords.setToolTipText("The term 'stop words' comes from Natural Language Processing where they are common words that will be excluded from content.\nIf a word exists in this list before running, then it will be excluded from output.")
            self.cbExclusions.setToolTipText("If the option is selected it will be applied when run.\nThe text field contains a comma separated list of values.\nIf any of these values exists in a potential link found, then it will be excluded from the final list.\nThere is a initial default list determined by the DEFAULT_EXCLUSIONS constant, but you can change this and save your settings.\nIf the option is not selected, all links will be returned.")
            self.inExclusions.setToolTipText("If the option is selected it will be applied when run. The text field contains a comma separated list of values.\nIf any of these values exists in a potential link found, then it will be excluded from the final list.\nThere is a initial default list determined by the DEFAULT_EXCLUSIONS constant, but you can change this and save your settings.\nIf the option is not selected, all links will be returned.")
        else:
            self.lblRequestParams.setToolTipText("")
            self.cbParamUrl.setToolTipText("")
            self.cbParamBody.setToolTipText("")
            self.cbParamMultiPart.setToolTipText("")
            self.cbParamJson.setToolTipText("")
            self.cbParamCookie.setToolTipText("")
            self.cbParamXml.setToolTipText("")
            self.cbParamXmlAttr.setToolTipText("")
            self.lblResponseParams.setToolTipText("")
            self.cbParamJSONResponse.setToolTipText("")
            self.cbParamXMLResponse.setToolTipText("")
            self.cbParamInputField.setToolTipText("")
            self.cbParamJSVars.setToolTipText("")
            self.cbParamFromLinks.setToolTipText("")
            self.cbReportSusParams.setToolTipText("")
            self.cbWordLower.setToolTipText("")
            self.cbWordPlurals.setToolTipText("")
            self.cbWordPaths.setToolTipText("")
            self.cbWordParams.setToolTipText("")
            self.cbWordComments.setToolTipText("")
            self.cbWordImgAlt.setToolTipText("")
            self.cbWordDigits.setToolTipText("")
            self.lblWordsMaxLen.setToolTipText("")
            self.inWordsMaxlen.setToolTipText("")
            self.cbToolTips.setToolTipText("")
            self.cbIncludePathWords.setToolTipText("")
            self.cbSiteMapEndpoints.setToolTipText("")
            self.cbRelativeLinks.setToolTipText("")
            self.cbLinkPrefix.setToolTipText("")
            self.inLinkPrefix.setToolTipText("")
            self.cbLinkPrefixScope.setToolTipText("")
            self.cbUnPrefixed.setToolTipText("")
            self.cbSaveFile.setToolTipText("")
            self.inSaveDir.setToolTipText("")
            self.btnChooseDir.setToolTipText("")
            self.cbShowSusParams.setToolTipText("")
            self.cbShowQueryString.setToolTipText("")
            self.inQueryStringVal.setToolTipText("")
            self.btnRestoreDefaults.setToolTipText("")
            self.btnSave.setToolTipText("")
            self.progBar.setToolTipText("")
            self.progStage.setToolTipText("")
            self.cbShowParamOrigin.setToolTipText("")
            self.cbShowLinkOrigin.setToolTipText("")
            self.cbInScopeOnly.setToolTipText("")
            self.lblLinkFilter.setToolTipText("")
            self.cbLinkFilterNeg.setToolTipText("")
            self.cbLinkCaseSens.setToolTipText("")
            self.inLinkFilter.setToolTipText("")
            self.cbShowWordOrigin.setToolTipText("")
            self.lblStopWords.setToolTipText("")
            self.inStopWords.setToolTipText("")
            self.cbExclusions.setToolTipText("")
            self.inExclusions.setToolTipText("")
    
    def cbToolTips_clicked(self ,e=None):
        self.setContextHelp(self.cbToolTips.isSelected())
        
    def _createUI(self):
        """
        Creates the Java Swing UI for GAP
        """
        # Derive the default font and size
        test = JLabel()
        FONT_FAMILY = test.getFont().getFamily()
        FONT_SIZE = test.getFont().getSize()

        # Create a font for headers and other non standard stuff
        FONT_HEADER = Font(FONT_FAMILY, Font.BOLD, FONT_SIZE + 2)
        FONT_HELP = Font(FONT_FAMILY, Font.BOLD, FONT_SIZE)
        FONT_GAP_MODE = Font(FONT_FAMILY, Font.BOLD, FONT_SIZE)
        FONT_OPTIONS = Font(FONT_FAMILY, Font.BOLD, FONT_SIZE - 2)

        # Links section
        self.lblLinkOptions = JLabel("Links mode options:")
        self.lblLinkOptions.setFont(FONT_HEADER)
        self.lblLinkOptions.setForeground(COLOR_BURP_ORANGE)
        
        # Parameter sections
        self.lblWhichParams = JLabel("Parameters mode options:")
        self.lblWhichParams.setFont(FONT_HEADER)
        self.lblWhichParams.setForeground(COLOR_BURP_ORANGE)

        # Request parameter section
        self.lblRequestParams = JLabel("REQUEST PARAMETERS")
        fnt = self.lblRequestParams.getFont()
        self.lblRequestParams.setFont(fnt.deriveFont(fnt.getStyle() | Font.BOLD))
        self.cbParamUrl = self.defineCheckBox("Query string params")
        self.cbParamBody = self.defineCheckBox("Message body params")
        self.cbParamMultiPart = self.defineCheckBox("Param attribute in multi-part message body")
        self.cbParamJson = self.defineCheckBox("JSON params")
        self.cbParamCookie = self.defineCheckBox("Cookie names", False)
        self.cbParamXml = self.defineCheckBox("Items of data in XML structure", False)
        self.cbParamXmlAttr = self.defineCheckBox("Value of tag attributes in XML structure", False)

        # Response parameter section
        self.lblResponseParams = JLabel("RESPONSE PARAMETERS")
        fnt = self.lblResponseParams.getFont()
        self.lblResponseParams.setFont(fnt.deriveFont(fnt.getStyle() | Font.BOLD))
        self.cbParamJSONResponse = self.defineCheckBox("JSON params", False)
        self.cbParamXMLResponse = self.defineCheckBox("Value of tag attributes in XML structure", False)
        self.cbParamInputField = self.defineCheckBox("Name and Id attributes of HTML input fields", False)
        self.cbParamJSVars = self.defineCheckBox("Javascript variables and constants", False)
        self.cbParamFromLinks = self.defineCheckBox("Params from links found", False)
        self.cbParamsEnabled = self.defineCheckBox("Parameters", True)
        self.cbParamsEnabled.addItemListener(self.cbParamsEnabled_clicked)
        self.cbLinksEnabled = self.defineCheckBox("Links", True)
        self.cbLinksEnabled.addItemListener(self.cbLinksEnabled_clicked)
        self.cbWordsEnabled = self.defineCheckBox("Words", True)
        self.cbWordsEnabled.addItemListener(self.cbWordsEnabled_clicked)

        # Words sections
        self.lblWhichWords = JLabel("Words mode options:")
        self.lblWhichWords.setFont(FONT_HEADER)
        self.lblWhichWords.setForeground(COLOR_BURP_ORANGE)

        # Request words section
        self.cbWordPlurals = self.defineCheckBox("Create singular/plural word?")
        self.cbWordPaths = self.defineCheckBox("Include URL path words?")
        self.cbWordParams = self.defineCheckBox("Include potential params?")
        self.cbWordComments = self.defineCheckBox("Include HTML comments?")
        self.cbWordImgAlt = self.defineCheckBox("Include IMG ALT attribute?")
        self.cbWordDigits = self.defineCheckBox("Include words with digits?")
        self.cbWordLower = self.defineCheckBox("Create lowercase words?")
        self.lblWordsMaxLen = JLabel("Maximum length of words")
        self.lblWordsMaxLen2 = JLabel("(min. 3 - excludes plurals)")
        self.inWordsMaxlen = JTextField("", 2 ,actionPerformed=self.checkMaxWordsLen)

        # Set the Help button as an icon
        # NOTE: This has been commented out because I could not get it to display correctly at different font size settings
        """ 
        imageUrl = URL(HELP_ICON)         
        img = ImageIO.read(imageUrl)
        resizedImg = img.getScaledInstance(37, 37, Image.SCALE_DEFAULT)       
        imgIcon = ImageIcon(resizedImg)
        self.btnHelp = JButton(imgIcon, actionPerformed=self.btnHelp_clicked)
        self.btnHelp.setContentAreaFilled(False)
        self.btnHelp.setBorderPainted(False)
        """
        # If can't set as an icon, set as a normal button
        self.lblHelp = JLabel("Click for help -->")
        self.lblHelp.setFont(FONT_GAP_MODE)
        self.lblHelp.setForeground(COLOR_BURP_ORANGE)
        self.btnHelp = JButton("?", actionPerformed=self.btnHelp_clicked)
        self.btnHelp.setFont(FONT_HELP)
        self.btnHelp.setForeground(Color.WHITE)
        self.btnHelp.setBorder(
            BorderFactory.createLineBorder(COLOR_BURP_ORANGE, 2, True)
        )
        self.btnHelp.setContentAreaFilled(True)
        self.btnHelp.setBackground(COLOR_BURP_ORANGE)
        self.btnHelp.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
        self.grpHelp = JPanel()
        self.grpHelp.setBorder(
            BorderFactory.createLineBorder(COLOR_BURP_ORANGE, 2, True)
        )
        self.grpHelp.add(self.lblHelp)
        self.grpHelp.add(self.btnHelp)
        self.btnHelp.setToolTipText("Click me for help!")
        
        # Set KoFi button
        try:
            initialImg = ImageIO.read(URL(URL_KOFI_BUTTON))
            width = int(round(self.grpHelp.getPreferredSize().width * 0.8))
            height = int(round(self.grpHelp.getPreferredSize().height * 0.85))
            scaledImg = initialImg.getScaledInstance(width, height, Image.SCALE_SMOOTH)
            self.grpKoFi = JButton(ImageIcon(scaledImg),actionPerformed=self.btnKoFi_clicked)
            self.grpKoFi.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
            self.grpKoFi.setToolTipText("Buy Me a Coffee!")
            self.grpKoFi.setBorderPainted(False)
            self.grpKoFi.setContentAreaFilled(False)
        except:
            self.btnKoFi = JButton("Buy Me a Coffee!",actionPerformed=self.btnKoFi_clicked)
            self.btnKoFi.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
            self.btnKoFi.setFont(FONT_HELP)
            self.btnKoFi.setForeground(Color.WHITE)
            self.btnKoFi.setBorder(
                BorderFactory.createLineBorder(COLOR_BURP_ORANGE, 2, True)
            )
            self.btnKoFi.setContentAreaFilled(True)
            self.btnKoFi.setBackground(COLOR_BURP_ORANGE)
            self.grpKoFi = JPanel()
            self.grpKoFi.setBorder(
                BorderFactory.createLineBorder(COLOR_BURP_ORANGE, 2, True)
            )
            self.grpKoFi.add(self.btnKoFi)

        # Set the GAP logo
        try:
            initialImg = ImageIO.read(URL(URL_GAP_LOGO))
            width = 300
            height = 30
            scaledImg = initialImg.getScaledInstance(width, height, Image.SCALE_SMOOTH)
            self.btnLogo = JButton(ImageIcon(scaledImg),actionPerformed=self.btnLogo_clicked)
            self.btnLogo.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
            self.btnLogo.setToolTipText("Check out my Github page")
            self.btnLogo.setBorder(BorderFactory.createEmptyBorder())
        except:
            self.btnLogo = JButton()
            self.btnLogo.setVisible(False)
        
        # GAP Mode group
        self.lblMode = JLabel("GAP Mode: ")
        self.lblMode.setFont(FONT_GAP_MODE)
        self.lblMode.setForeground(COLOR_BURP_ORANGE)
        self.grpMode = JPanel()
        self.grpMode.setBorder(
            BorderFactory.createLineBorder(COLOR_BURP_ORANGE, 2, True)
        )
        self.grpMode.add(self.btnLogo)
        self.grpMode.add(self.lblMode)
        self.grpMode.add(self.cbParamsEnabled)
        self.grpMode.add(self.cbLinksEnabled)
        self.grpMode.add(self.cbWordsEnabled)
        
        # Output options section
        self.lblOutputOptions = JLabel("Other options:")
        self.lblOutputOptions.setFont(FONT_HEADER)
        self.lblOutputOptions.setForeground(COLOR_BURP_ORANGE)
        self.cbToolTips = self.defineCheckBox("Show contextual help", True)
        self.cbToolTips.addItemListener(self.cbToolTips_clicked)
        self.cbToolTips.setForeground(COLOR_BURP_ORANGE)
        
        self.cbReportSusParams = self.defineCheckBox("Report \"sus\" parameters?", True)
        self.cbIncludePathWords = self.defineCheckBox("Include URL path words?", False)
        self.cbSiteMapEndpoints = self.defineCheckBox("Include site map endpoints?", False)
        self.cbRelativeLinks = self.defineCheckBox("Include relative links?")
        self.cbLinkPrefix = self.defineCheckBox("Prefix with link(s):")
        self.cbLinkPrefix.addItemListener(self.cbLinkPrefix_clicked)
        self.inLinkPrefix = JTextField(30,actionPerformed=self.checkLinkPrefix)
        self.cbLinkPrefixScope = self.defineCheckBox("Prefix with selected Target(s)")
        self.cbLinkPrefixScope.addItemListener(self.cbLinkPrefixScope_clicked)
        self.cbLinkPrefixScope.setSelected(False)
        self.cbUnPrefixed = self.defineCheckBox("Also include un-prefixed links?")
        self.cbSaveFile = self.defineCheckBox("Auto save output to directory")
        self.cbSaveFile.addItemListener(self.cbSaveFile_clicked)
        self.inSaveDir = JTextField(30)
        self.inSaveDir.setEditable(False)
        self.btnChooseDir = JButton("Choose...", actionPerformed=self.btnChooseDir_clicked)
        self.cbShowSusParams = self.defineCheckBox("Show \"sus\"") 
        self.cbShowSusParams.setEnabled(False)
        self.cbShowSusParams.addItemListener(self.changeParamDisplay)
        self.cbShowQueryString = self.defineCheckBox("Show query string with value", False)
        self.cbShowQueryString.setEnabled(False)
        self.cbShowQueryString.addItemListener(self.cbShowQueryString_clicked)
        self.inQueryStringVal = JTextField(5)
        
        # The Restore/Save section
        self.btnSave = JButton("Save options", actionPerformed=self.btnSave_clicked)
        self.btnRestoreDefaults = JButton("Restore defaults", actionPerformed=self.btnRestoreDefaults_clicked)
        self.btnCancel = JButton("   COMPLETED    ", actionPerformed=self.btnCancel_clicked)
        self.btnCancel.setBackground(COLOR_BURP_ORANGE)
        self.btnCancel.setForeground(Color.WHITE)
        self.btnCancel.setFont(self.btnCancel.getFont().deriveFont(Font.BOLD))
        self.btnCancel.setVisible(False)
        # Create progress bar
        self.progBar = JProgressBar()
        self.progBar.setValue(0)
        self.progBar.setStringPainted(True)
        self.progBar.setVisible(False)
        self.progStage = JLabel()
        self.progStage.setVisible(False)
        self.progStage.setFont(FONT_HEADER)
        self.progStage.setForeground(COLOR_BURP_ORANGE)
        
        self.grpConfig = JPanel()
        self.grpConfig.add(self.btnRestoreDefaults)
        self.grpConfig.add(self.btnSave)
        self.grpConfig.add(JLabel("    "))
        self.grpConfig.add(self.btnCancel)
        self.grpConfig.add(self.progBar)
        self.grpConfig.add(self.progStage)

        # Potential parameters found section
        self.lblParamList = JLabel("Potential params found:")
        self.lblParamList.setFont(FONT_HEADER)
        self.lblParamList.setForeground(COLOR_BURP_ORANGE)
        self.outParamList = JTextArea(30, 100)
        self.outParamList.setLineWrap(False)
        self.outParamList.setEditable(False)
        self.scroll_outParamList = JScrollPane(self.outParamList)
        self.scroll_outParamList.setVerticalScrollBarPolicy(
            ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED
        )
        self.scroll_outParamList.setHorizontalScrollBarPolicy(
            ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED
        )
        self.cbShowParamOrigin = self.defineCheckBox("Show origin", False)
        self.cbShowParamOrigin.setFont(FONT_OPTIONS)
        self.cbShowParamOrigin.setVisible(True)
        self.cbShowParamOrigin.setEnabled(False)
        self.cbShowParamOrigin.addItemListener(self.changeParamDisplay)
        self.outParamSus = JTextArea(30, 100)
        self.outParamSus.setLineWrap(True)
        self.outParamSus.setEditable(False)
        self.outParamQuery = JTextArea(30, 100)
        self.outParamQuery.setLineWrap(True)
        self.outParamQuery.setEditable(False)
        
        # Potential links found section
        self.lblLinkList = JLabel("Potential links found:")
        self.lblLinkList.setFont(FONT_HEADER)
        self.lblLinkList.setForeground(COLOR_BURP_ORANGE)
        self.outLinkList = JTextArea(30, 100)
        self.outLinkList.setLineWrap(False)
        self.outLinkList.setEditable(False)
        self.scroll_outLinkList = JScrollPane(self.outLinkList)
        self.scroll_outLinkList.setVerticalScrollBarPolicy(
            ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED
        )
        self.scroll_outLinkList.setHorizontalScrollBarPolicy(
            ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED
        )
        self.cbShowLinkOrigin = self.defineCheckBox("Show origin endpoint", False)
        self.cbShowLinkOrigin.setFont(FONT_OPTIONS)
        self.cbShowLinkOrigin.setVisible(True)
        self.cbShowLinkOrigin.setEnabled(False)
        self.cbShowLinkOrigin.addItemListener(self.changeLinkDisplay)
        self.cbInScopeOnly = self.defineCheckBox("In scope only", False)
        self.cbInScopeOnly.setFont(FONT_OPTIONS)
        self.cbInScopeOnly.setVisible(True)
        self.cbInScopeOnly.setEnabled(False)
        self.cbInScopeOnly.addItemListener(self.changeLinkDisplay)
        self.lblLinkFilter = JLabel("Link filter:")
        self.lblLinkFilter.setEnabled(False)
        self.btnFilter = JButton("Apply filter", actionPerformed=self.btnFilter_clicked)
        self.btnFilter.setEnabled(False)
        self.cbLinkFilterNeg = self.defineCheckBox("Negative match", False)
        self.cbLinkFilterNeg.setEnabled(False)
        self.cbLinkCaseSens = self.defineCheckBox("Case sensitive", False)
        self.cbLinkCaseSens.setEnabled(False)
        self.inLinkFilter = JTextField(10)
        self.keyListen = CustomKeyListener(self.btnFilter)
        self.inLinkFilter.addKeyListener(self.keyListen)
        self.inLinkFilter.setEnabled(False)
        self.grpLinkFilter = JPanel()
        self.grpLinkFilter.add(self.lblLinkFilter)
        self.grpLinkFilter.add(self.inLinkFilter)
        self.grpLinkFilter.add(self.cbLinkFilterNeg)
        self.grpLinkFilter.add(self.cbLinkCaseSens)
        self.grpLinkFilter.add(self.btnFilter)
        
        # Potential words found section
        if WORDLIST_IMPORT_ERROR != "":
            self.lblWordList = JLabel("Words found - UNAVAILABLE:")
        else:
            self.lblWordList = JLabel("Words found:")
        self.lblWordList.setFont(FONT_HEADER)
        self.lblWordList.setForeground(COLOR_BURP_ORANGE)
        self.cbShowWordOrigin = self.defineCheckBox("Show origin", False)
        self.cbShowWordOrigin.setFont(FONT_OPTIONS)
        self.cbShowWordOrigin.setVisible(True)
        self.cbShowWordOrigin.setEnabled(False)
        self.cbShowWordOrigin.addItemListener(self.changeWordDisplay)
        self.outWordList = JTextArea(30, 100)
        if WORDLIST_IMPORT_ERROR != "":
            self.outWordList.setWrapStyleWord(True)
            self.outWordList.setLineWrap(True)
        else:
            self.outWordList.setLineWrap(False)
        self.outWordList.setEditable(False)
        if WORDLIST_IMPORT_ERROR != "":
            self.outWordList.text = WORDLIST_IMPORT_ERROR
        self.scroll_outWordList = JScrollPane(self.outWordList)
        self.scroll_outWordList.setVerticalScrollBarPolicy(
            ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED
        )
        self.scroll_outWordList.setHorizontalScrollBarPolicy(
            ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED
        )
        self.lblStopWords = JLabel("Stop words:")
        self.inStopWords = JTextField(30)
        
        # Initialise text fields to hold variations of outLinkList JTextArea
        self.txtLinksWithURL = ""
        self.txtLinksOnly = ""
        self.txtLinksWithURLInScopeOnly = ""
        self.txtLinksOnlyInScopeOnly = ""
        self.txtLinksFiltered = ""

        # Initialise text fields to hold variations of outParamList JTextArea
        self.txtParamsWithURL = ""
        self.txtParamsOnly = ""
        self.txtParamsSusWithURL = ""
        self.txtParamsSusOnly = ""
        self.txtParamsQuery = ""
        
        # Initialise text fields to hold variations of outWordList JTextArea
        self.txtWordsWithURL = ""
        self.txtWordsOnly = ""
        
        # Definition of config tab
        self.tab = JPanel()
        layout = GroupLayout(self.tab)
        self.tab.setLayout(layout)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)

        # Set up a field for comma separated exclusion strings
        #self.lblExclusions = JLabel(" Link exclusions:")
        self.cbExclusions = self.defineCheckBox("Link exclusions:", True)
        self.cbExclusions.setFont(FONT_OPTIONS)
        self.cbExclusions.setVisible(True)
        self.cbExclusions.setEnabled(False)
        self.cbExclusions.addItemListener(self.changeLinkExclusions)
        self.inExclusions = JTextField(300)

        # Debug info
        self.txtDebug = JTextArea(85, 1)
        self.txtDebug.setVisible(False)
        self.txtDebug.setLineWrap(True)
        self.txtDebug.setEditable(False)
        self.txtDebugDetail = JTextArea(85, 1)
        self.txtDebugDetail.setVisible(False)
        self.txtDebugDetail.setLineWrap(True)
        self.txtDebugDetail.setEditable(False)
        self.logContentType = False
        
        # Restore saved config settings
        self.restoreSavedConfig()

        # Determine whether to "show context help"
        self.setContextHelp(self.cbToolTips.isSelected())

        # Set UI layout
        layout.setHorizontalGroup(
            layout.createParallelGroup()
            .addGroup(
                layout.createSequentialGroup()
                .addGroup(
                    layout.createParallelGroup()
                    .addComponent(
                            self.grpMode,
                            GroupLayout.PREFERRED_SIZE,
                            GroupLayout.PREFERRED_SIZE,
                            GroupLayout.PREFERRED_SIZE,
                            )
                    .addComponent(self.lblWhichParams)
                    .addGroup(
                        layout.createSequentialGroup()
                        .addGroup(
                            layout.createParallelGroup()
                            .addComponent(self.cbIncludePathWords)
                            .addComponent(self.lblRequestParams)
                            .addComponent(self.cbParamUrl)
                            .addComponent(self.cbParamBody)
                            .addComponent(self.cbParamMultiPart)
                            .addComponent(self.cbParamJson)
                            .addComponent(self.cbParamCookie)
                            .addComponent(self.cbParamXml)
                            .addComponent(self.cbParamXmlAttr)
                        )
                        .addGroup(
                            layout.createParallelGroup()
                            .addComponent(self.cbReportSusParams)
                            .addComponent(self.lblResponseParams)
                            .addComponent(self.cbParamJSONResponse)
                            .addComponent(self.cbParamXMLResponse)
                            .addComponent(self.cbParamInputField)
                            .addComponent(self.cbParamJSVars)
                            .addComponent(self.cbParamFromLinks)
                            .addGroup(
                                layout.createSequentialGroup()
                                .addComponent(
                                    self.grpHelp,
                                    GroupLayout.PREFERRED_SIZE,
                                    GroupLayout.PREFERRED_SIZE,
                                    GroupLayout.PREFERRED_SIZE,
                                )
                                .addComponent(self.grpKoFi,
                                    GroupLayout.PREFERRED_SIZE,
                                    GroupLayout.PREFERRED_SIZE,
                                    GroupLayout.PREFERRED_SIZE,)
                            )
                        )
                    )
                    .addComponent(self.lblLinkOptions)
                    .addGroup(
                        layout.createSequentialGroup()
                        .addComponent(self.cbLinkPrefixScope)
                        .addComponent(self.cbLinkPrefix)
                        .addComponent(self.inLinkPrefix)
                    )
                    .addGroup(
                        layout.createSequentialGroup()
                        .addComponent(self.cbUnPrefixed)
                        .addComponent(self.cbSiteMapEndpoints)
                        .addComponent(self.cbRelativeLinks)
                    )
                    .addComponent(self.lblWhichWords)
                    .addGroup(
                        layout.createSequentialGroup()
                        .addGroup(
                            layout.createParallelGroup()
                            .addComponent(self.cbWordLower)
                            .addComponent(self.cbWordPlurals)
                            .addGroup(
                                layout.createSequentialGroup()
                                .addComponent(self.lblWordsMaxLen)
                                .addComponent(
                                    self.inWordsMaxlen,
                                    GroupLayout.PREFERRED_SIZE,
                                    GroupLayout.PREFERRED_SIZE,
                                    GroupLayout.PREFERRED_SIZE,
                                )
                            )       
                        )
                        .addGroup(
                            layout.createParallelGroup()
                            .addComponent(self.cbWordComments)
                            .addComponent(self.cbWordImgAlt)
                            .addComponent(self.lblWordsMaxLen2)
                        )
                        .addGroup(
                            layout.createParallelGroup()
                            .addComponent(self.cbWordDigits)
                            .addComponent(self.cbWordPaths)
                            .addComponent(self.cbWordParams)
                        )
                    )
                    .addGroup(
                        layout.createSequentialGroup()
                        .addComponent(self.lblOutputOptions)
                        .addComponent(self.cbToolTips)
                    )
                    .addGroup(
                        layout.createSequentialGroup()
                        .addComponent(self.cbSaveFile)
                        .addComponent(self.inSaveDir)
                        .addComponent(self.btnChooseDir)
                    )
                    .addComponent(
                        self.grpConfig,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                    )
                    .addComponent(self.txtDebug,
                        GroupLayout.DEFAULT_SIZE,
                        GroupLayout.DEFAULT_SIZE,
                        GroupLayout.DEFAULT_SIZE,
                    )
                    .addComponent(self.txtDebugDetail,
                        GroupLayout.DEFAULT_SIZE,
                        GroupLayout.DEFAULT_SIZE,
                        GroupLayout.DEFAULT_SIZE,
                    )
                )
                .addGroup(
                    layout.createParallelGroup()
                    .addGroup(
                        layout.createSequentialGroup()
                        .addGroup(
                            layout.createParallelGroup()
                            .addGroup(
                                layout.createSequentialGroup()
                                .addComponent(self.lblParamList)
                                .addComponent(self.cbShowParamOrigin)
                            )
                            .addComponent(self.scroll_outParamList)
                            .addGroup(
                                layout.createSequentialGroup()
                                .addComponent(self.cbShowSusParams)
                                .addComponent(self.cbShowQueryString)
                                .addComponent(
                                    self.inQueryStringVal,
                                    GroupLayout.PREFERRED_SIZE,
                                    GroupLayout.PREFERRED_SIZE,
                                    GroupLayout.PREFERRED_SIZE,
                                )
                            )
                        )
                        .addGroup(
                            layout.createParallelGroup()
                            .addGroup(
                                layout.createSequentialGroup()
                                .addComponent(self.lblWordList)
                                .addComponent(self.cbShowWordOrigin)
                            )
                            .addComponent(self.scroll_outWordList)
                            .addGroup(
                                layout.createSequentialGroup()
                                .addComponent(self.lblStopWords)
                                .addComponent(self.inStopWords)
                            )
                        )
                    )
                    .addGroup(
                        layout.createSequentialGroup()
                        .addComponent(self.lblLinkList)
                        .addComponent(self.cbShowLinkOrigin)
                        .addComponent(self.cbInScopeOnly)
                    )
                    .addComponent(self.scroll_outLinkList)
                    .addComponent(
                        self.grpLinkFilter,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                    )
                    .addGroup(
                        layout.createSequentialGroup()
                        .addComponent(self.cbExclusions)
                        .addComponent(
                            self.inExclusions,
                            GroupLayout.DEFAULT_SIZE,
                            GroupLayout.DEFAULT_SIZE,
                            GroupLayout.DEFAULT_SIZE,
                        )
                    )
                )
            )
        )

        layout.setVerticalGroup(
            layout.createSequentialGroup()
            .addGroup(
                layout.createParallelGroup()
                .addGroup(
                    layout.createSequentialGroup()
                    .addComponent(
                                self.grpMode,
                                GroupLayout.PREFERRED_SIZE,
                                GroupLayout.PREFERRED_SIZE,
                                GroupLayout.PREFERRED_SIZE,
                                )
                    .addComponent(self.lblWhichParams)
                    .addGroup(
                        layout.createParallelGroup()
                        .addGroup(
                            layout.createSequentialGroup()
                            .addComponent(self.cbIncludePathWords)
                            .addComponent(self.lblRequestParams)
                            .addComponent(self.cbParamUrl)
                            .addComponent(self.cbParamBody)
                            .addComponent(self.cbParamMultiPart)
                            .addComponent(self.cbParamJson)
                            .addComponent(self.cbParamCookie)
                            .addComponent(self.cbParamXml)
                            .addComponent(self.cbParamXmlAttr)
                        )
                        .addGroup(
                            layout.createSequentialGroup()
                            .addComponent(self.cbReportSusParams)
                            .addComponent(self.lblResponseParams)
                            .addComponent(self.cbParamJSONResponse)
                            .addComponent(self.cbParamXMLResponse)
                            .addComponent(self.cbParamInputField)
                            .addComponent(self.cbParamJSVars)
                            .addComponent(self.cbParamFromLinks)
                            .addGroup(
                            layout.createParallelGroup()
                            .addComponent(
                                self.grpHelp,
                                GroupLayout.PREFERRED_SIZE,
                                GroupLayout.PREFERRED_SIZE,
                                GroupLayout.PREFERRED_SIZE,
                            )
                            .addComponent(self.grpKoFi,
                                GroupLayout.PREFERRED_SIZE,
                                GroupLayout.PREFERRED_SIZE,
                                GroupLayout.PREFERRED_SIZE,)
                        )
                        )
                    )
                    .addComponent(self.lblLinkOptions)
                    .addGroup(
                        layout.createParallelGroup()
                        .addComponent(self.cbLinkPrefixScope)
                        .addComponent(self.cbLinkPrefix)
                        .addComponent(self.inLinkPrefix,
                            GroupLayout.PREFERRED_SIZE,
                            GroupLayout.PREFERRED_SIZE,
                            GroupLayout.PREFERRED_SIZE,)
                    )
                    .addGroup(
                        layout.createParallelGroup()
                        .addComponent(self.cbUnPrefixed)
                        .addComponent(self.cbSiteMapEndpoints)
                        .addComponent(self.cbRelativeLinks)
                    )
                    .addComponent(self.lblWhichWords)
                    .addGroup(
                        layout.createParallelGroup()
                        .addGroup(
                            layout.createSequentialGroup()
                            .addComponent(self.cbWordLower)
                            .addComponent(self.cbWordPlurals)
                            .addGroup(
                                layout.createParallelGroup()
                                .addComponent(self.lblWordsMaxLen)
                                .addComponent(
                                    self.inWordsMaxlen,
                                    GroupLayout.PREFERRED_SIZE,
                                    GroupLayout.PREFERRED_SIZE,
                                    GroupLayout.PREFERRED_SIZE,
                                )
                            )
                        )
                        .addGroup(
                            layout.createSequentialGroup()
                            .addComponent(self.cbWordComments)
                            .addComponent(self.cbWordImgAlt)
                            .addComponent(self.lblWordsMaxLen2)
                        )
                        .addGroup(
                            layout.createSequentialGroup()
                            .addComponent(self.cbWordDigits)
                            .addComponent(self.cbWordPaths)
                            .addComponent(self.cbWordParams)
                        )
                    )
                    .addGroup(
                        layout.createParallelGroup()
                        .addComponent(self.lblOutputOptions)
                        .addComponent(self.cbToolTips)
                    )
                    .addGroup(
                        layout.createParallelGroup()
                        .addComponent(self.cbSaveFile)
                        .addComponent(
                            self.inSaveDir,
                            GroupLayout.PREFERRED_SIZE,
                            GroupLayout.PREFERRED_SIZE,
                            GroupLayout.PREFERRED_SIZE,
                        )
                        .addComponent(self.btnChooseDir)
                    )
                    .addComponent(
                        self.grpConfig,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                    )
                    .addComponent(self.txtDebug,
                        GroupLayout.DEFAULT_SIZE,
                        GroupLayout.DEFAULT_SIZE,
                        GroupLayout.DEFAULT_SIZE,
                    )
                    .addComponent(self.txtDebugDetail,
                        GroupLayout.DEFAULT_SIZE,
                        GroupLayout.DEFAULT_SIZE,
                        GroupLayout.DEFAULT_SIZE,
                    )
                )
                .addGroup(
                    layout.createSequentialGroup()
                    .addGroup(
                        layout.createParallelGroup()
                        .addGroup(
                            layout.createSequentialGroup()
                            .addGroup(
                                layout.createParallelGroup()
                                .addComponent(self.lblParamList)
                                .addComponent(self.cbShowParamOrigin)
                            )
                            .addComponent(
                                self.scroll_outParamList,
                                GroupLayout.DEFAULT_SIZE,
                                GroupLayout.DEFAULT_SIZE,
                                GroupLayout.DEFAULT_SIZE,
                            )
                            .addGroup(
                                layout.createParallelGroup()
                                .addComponent(self.cbShowSusParams)
                                .addComponent(self.cbShowQueryString)
                                .addComponent(
                                    self.inQueryStringVal,
                                    GroupLayout.PREFERRED_SIZE,
                                    GroupLayout.PREFERRED_SIZE,
                                    GroupLayout.PREFERRED_SIZE,
                                )
                            )
                        )
                        .addGroup(
                            layout.createSequentialGroup()
                            .addGroup(
                                layout.createParallelGroup()
                                .addComponent(self.lblWordList)
                                .addComponent(self.cbShowWordOrigin)
                            )
                            .addComponent(
                                self.scroll_outWordList,
                                GroupLayout.DEFAULT_SIZE,
                                GroupLayout.DEFAULT_SIZE,
                                GroupLayout.DEFAULT_SIZE,
                            )
                            .addGroup(
                                layout.createParallelGroup()
                                .addComponent(self.lblStopWords)
                                .addComponent(self.inStopWords,
                                    GroupLayout.PREFERRED_SIZE,
                                    GroupLayout.PREFERRED_SIZE,
                                    GroupLayout.PREFERRED_SIZE,)
                            )
                        )
                    )
                    .addGroup(
                        layout.createParallelGroup()
                        .addComponent(self.lblLinkList)
                        .addComponent(self.cbShowLinkOrigin)
                        .addComponent(self.cbInScopeOnly)
                    )
                    .addComponent(
                        self.scroll_outLinkList,
                        GroupLayout.DEFAULT_SIZE,
                        GroupLayout.DEFAULT_SIZE,
                        GroupLayout.DEFAULT_SIZE,
                    )
                    .addComponent(
                        self.grpLinkFilter,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                    )
                    .addGroup(
                        layout.createParallelGroup()
                        .addComponent(self.cbExclusions)
                        .addComponent(
                            self.inExclusions,
                            GroupLayout.PREFERRED_SIZE,
                            GroupLayout.PREFERRED_SIZE,
                            GroupLayout.PREFERRED_SIZE,
                        )
                    )
                )
            )
        )

        self._callbacks.addSuiteTab(self)
   
    def btnLogo_clicked(self, e=None):
        """
        The event called when the Logo image is clicked. Open a browser tab to Github page
        """
        try:
            self.setTabDefaultColor()
        # If the user held down the Ctrl button when clicking the header, then hide the header
            if str(e).find("Shift+Button1") > 0:
                self.txtDebug.setVisible(True)
                self.txtDebug.text = "DEBUG TEXT WILL BE DISPLAYED"
                self.txtDebugDetail.setVisible(True)
                self.logContentType = True
            else:
                Desktop.getDesktop().browse(URI(URL_GITHUB))
        except:
            pass
    
    def btnKoFi_clicked(self, e=None):
        """
        The event called when the KoFi button is clicked. Open a browser tab to KoFi page
        """
        try:
            self.setTabDefaultColor()
            Desktop.getDesktop().browse(URI(URL_KOFI))
        except:
            pass
        
    def cbParamsEnabled_clicked(self, e=None):
        """
        The event called when the "Parameters" check box is clicked
        """
        self.setTabDefaultColor()
        if self.cbParamsEnabled.isSelected():
            self.setEnabledParamOptions(True)
            self.lblParamList.visible = True
            self.cbShowParamOrigin.visible = True
            if self.cbShowQueryString.isSelected():
                self.scroll_outParamList.setViewportView(self.outParamQuery)
            else:
                if self.cbShowSusParams.isSelected():
                    self.scroll_outParamList.setViewportView(self.outParamSus)
                else:
                    self.scroll_outParamList.setViewportView(self.outParamList)
            self.scroll_outParamList.visible = True
            self.cbShowSusParams.visible = True
            self.cbShowQueryString.visible = True
            self.inQueryStringVal.visible = True
            # Also remove the word option "Include potential parameters"
            self.cbWordParams.visible = True
        else:
            self.setEnabledParamOptions(False)
            self.lblParamList.visible = False
            self.cbShowParamOrigin.visible = False
            self.scroll_outParamList.visible = False
            self.cbShowSusParams.visible = False
            self.cbShowQueryString.visible = False
            self.inQueryStringVal.visible = False
            # If no other mode is selected, reselect Links
            if not self.cbLinksEnabled.isSelected() and not self.cbWordsEnabled.isSelected():
                self.cbLinksEnabled.setSelected(True)
            # Also show the word option "Include potential parameters"
            self.cbWordParams.visible = False
            
    def cbLinksEnabled_clicked(self, e=None):
        """
        The event called when the "Links" check box is clicked
        """
        self.setTabDefaultColor()
        if self.cbLinksEnabled.isSelected():
            self.setEnabledLinkOptions(True)
            self.lblLinkList.visible = True
            self.cbInScopeOnly.visible = True
            self.cbShowLinkOrigin.visible = True
            self.scroll_outLinkList.visible = True
            self.grpLinkFilter.visible = True
            self.cbExclusions.visible = True
            self.inExclusions.visible = True
        else:
            self.setEnabledLinkOptions(False)
            self.lblLinkList.visible = False
            self.cbInScopeOnly.visible = False
            self.cbShowLinkOrigin.visible = False
            self.scroll_outLinkList.visible = False
            self.grpLinkFilter.visible = False
            self.cbExclusions.visible = False
            self.inExclusions.visible = False
            # If no other mode is selected, reselect Params
            if not self.cbParamsEnabled.isSelected() and not self.cbWordsEnabled.isSelected():
                self.cbParamsEnabled.setSelected(True)
            
    def cbWordsEnabled_clicked(self, e=None):
        """
        The event called when the "Words" check box is clicked
        """
        self.setTabDefaultColor()
        if self.cbWordsEnabled.isSelected():
            self.setEnabledWordOptions(True)
            self.lblWordList.visible = True
            self.cbShowWordOrigin.visible = True
            self.scroll_outWordList.visible = True
            self.lblStopWords.visible = True
            self.inStopWords.visible = True
            if WORDLIST_IMPORT_ERROR != "":
                self.lblWordList.text = "Words found - UNAVAILABLE:"
        else:
            self.setEnabledWordOptions(False)
            self.lblWordList.visible = False
            self.cbShowWordOrigin.visible = False
            self.scroll_outWordList.visible = False
            self.lblStopWords.visible = False
            self.inStopWords.visible = False
            # If no other mode is selected, reselect Links
            if not self.cbParamsEnabled.isSelected() and not self.cbLinksEnabled.isSelected():
                self.cbLinksEnabled.setSelected(True)
                
    def getTabCaption(self):
        return "GAP"

    def getUiComponent(self):
        return self.tab

    def scopeChanged(self, e=None):
        """
        The event called when the scope has changed in Burp
        """
        # If the scope has change then clear the dictionary that contains links in scope
        self.dictCheckedLinks.clear()

    def defineCheckBox(self, caption, selected=True, enabled=True):
        """
        Used when creating check box controls
        """
        checkBox = JCheckBox(caption)
        checkBox.setSelected(selected)
        checkBox.setEnabled(enabled)
        return checkBox

    def cbLinkPrefix_clicked(self, e=None):
        """
        The event called when the "Link prefix" checkbox is changed
        """
        self.setTabDefaultColor()
        # Only enable the Link Prefix field and Un_Prefixed checkbox if the Link Prefix checkbox is selected
        if self.cbLinkPrefix.isSelected():
            self.inLinkPrefix.setEnabled(True)
            self.cbUnPrefixed.setEnabled(True)
            self.checkLinkPrefix()
        else:
            self.inLinkPrefix.setEnabled(False)
            if not self.cbLinkPrefixScope.isSelected():
                self.cbUnPrefixed.setEnabled(False)
            
    def cbSaveFile_clicked(self, e=None):
        """
        The event called when the "Auto save output directory" checkbox is changed
        """
        self.setTabDefaultColor()
        # Only enable the Save Directory field if the Save checkbox is selected
        if self.cbSaveFile.isSelected():
            self.inSaveDir.setEnabled(True)
        else:
            self.inSaveDir.setEnabled(False)

    def changeParamDisplay(self, e=None):
        """
        The Parameter event called when the "Show origin", "Show sus" or "Show query string with value" checkbox is changed
        """
        try:
            if self.cbShowParamOrigin.isEnabled():
                self.setTabDefaultColor()
                self.outParamList.text = "UPDATING..."
                
                # Only show the origin URLs if the Show origin checkbox is ticked
                # The list of params depends on the settings selected
                if self.cbShowParamOrigin.isSelected():
                    if self.cbShowSusParams.isSelected():
                        self.outParamList.text = self.txtParamsSusWithURL
                    else:
                        self.outParamList.text = self.txtParamsWithURL
                    self.scroll_outParamList.setViewportView(self.outParamList)
                    self.cbShowQueryString.setSelected(False)
                else:
                    if self.cbShowQueryString.isSelected():
                        if self.cbShowSusParams.isSelected():
                            if self.txtParamQuerySus == "" or self.txtParamQuerySus == "NO PARAMETERS FOUND":
                                index = 0
                                paramQuery = ""
                                self.outParamQuery.text = "UPDATING..."
                                for param in sorted(self.paramSus_list):
                                    self.checkIfCancel()
                                    # Build a list of parameters in a concatenated string with unique values
                                    paramQuery = paramQuery + param.split("  [")[0] + "=" + self.inQueryStringVal.text + str(index) + "&"
                                    index += 1
                                self.txtParamQuerySus = paramQuery.rstrip("&")
                            self.outParamQuery.text = self.txtParamQuerySus
                        else:
                            # Set the values if not already set
                            if self.txtParamQuery == "" or self.txtParamQuery == "NO PARAMETERS FOUND":
                                index = 0
                                paramQuery = ""
                                self.outParamQuery.text = "UPDATING..."
                                for param in sorted(self.param_list):
                                    self.checkIfCancel()
                                    # Build a list of parameters in a concatenated string with unique values
                                    paramQuery = paramQuery + param + "=" + self.inQueryStringVal.text + str(index) + "&"
                                    index += 1
                                self.txtParamQuery = paramQuery.rstrip("&")
                            self.outParamQuery.text = self.txtParamQuery
                            
                        self.scroll_outParamList.setViewportView(self.outParamQuery)

                        # Reposition the display of the Param list to the start
                        self.outParamQuery.setCaretPosition(0)
                    else:
                        if self.cbShowParamOrigin.isSelected():
                            if self.cbShowSusParams.isSelected():
                                self.outParamList.text = self.txtParamsSusWithURL
                            else:
                                self.outParamList.text = self.txtParamsWithURL
                        else:
                            if self.cbShowSusParams.isSelected():
                                self.outParamList.text = self.txtParamsSusOnly
                            else:
                                self.outParamList.text = self.txtParamsOnly
                        self.scroll_outParamList.setViewportView(self.outParamList)
                
                # Change the number of params in the "Potential param found" label depending if a filter is in place
                if self.cbShowParamOrigin.isSelected():
                    if self.cbShowSusParams.isSelected():
                        self.lblParamList.text = (
                            "Potential params found - " + str(self.countParamSusUnique) + " unique:"
                        )
                    else:
                        self.lblParamList.text = (
                        "Potential params found - " + str(self.countParamUnique) + " unique:"
                    )
                else:
                    if self.cbShowSusParams.isSelected():
                        self.lblParamList.text = (
                            "Potential params found - "
                            + str(self.countParamSus)
                            + " filtered:"
                        )
                    else:
                        self.lblParamList.text = (
                            "Potential params found - "
                            + str(self.countParam)
                            + " filtered:"
                        )
                    
                # Reposition the display of the Param list to the start
                self.outParamList.setCaretPosition(0)

        except Exception as e:
            self._stderr.println("changeParamDisplay 1")
            self._stderr.println(e)
  
    def changeLinkExclusions(self, e=None):
        """
        The event called when the "Link exclusions" checkbox is changed
        """
        try:
            if self.cbExclusions.isSelected():
                self.inExclusions.setEnabled(True)
            else:
                self.inExclusions.setEnabled(False)
                
        except Exception as e:
            self._stderr.println("changeLinkExclusions 1")
            self._stderr.println(e)    
        
    def changeWordDisplay(self, e=None):
        """
        The Word event called when the "Show origin" checkbox is changed
        """
        try:
            self.outWordList.text = "UPDATING..."
            
            # Only show the origin URLs if the Show origin checkbox is ticked
            # The list of words depends on the settings selected
            if self.cbShowWordOrigin.isSelected():
                self.outWordList.text = self.txtWordsWithURL
            else:
                self.outWordList.text = self.txtWordsOnly
            
            # Change the number of words in the "Words found" label depending if a filter is in place
            #if str(self.countWordUnique) == str(self.outWordList.getLineCount()-1):
            if self.cbShowWordOrigin.isSelected():
                self.lblWordList.text = (
                    "Words found - " + str(self.countWordUnique) + " unique:"
                )
            else:
                self.lblWordList.text = (
                    "Words found - "
                    + str(self.outWordList.getLineCount())
                    + " filtered:"
                )
                
            # Reposition the display of the Word list to the start
            self.outWordList.setCaretPosition(0)
        except Exception as e:
            self._stderr.println("changeWordDisplay 1")
            self._stderr.println(e)
                  
    def changeLinkDisplay(self, e=None):
        """
        The event called when the "Show origin endpoint" checkbox is changed
        """
        try:
            self.outLinkList.text = "UPDATING..."
            
            # Only show the origin URLs if the Show origin endpoint checkbox is ticked
            # The list of links depends on the settings selected
            if self.cbShowLinkOrigin.isSelected():
                if self.cbInScopeOnly.isSelected():
                    self.outLinkList.text = self.txtLinksWithURLInScopeOnly
                else:
                    self.outLinkList.text = self.txtLinksWithURL
            else:
                if self.cbInScopeOnly.isSelected():
                    self.outLinkList.text = self.txtLinksOnlyInScopeOnly
                else:
                    self.outLinkList.text = self.txtLinksOnly

            # Change the number of links in the "Potential links found" label depending if a filter is in place
            if self.cbShowLinkOrigin.isSelected() and not self.cbInScopeOnly.isSelected():
                self.lblLinkList.text = (
                    "Potential links found - " + str(self.countLinkUnique) + " unique:"
                )
            else:
                self.lblLinkList.text = (
                    "Potential links found - "
                    + str(self.outLinkList.getLineCount())
                    + " filtered:"
                )

            # If there is a filter in place, apply it again
            if self.btnFilter.text == "Clear filter":
                self.btnFilter_clicked()

            # Reposition the display of the Link list to the start
            self.outLinkList.setCaretPosition(0)
        except Exception as e:
            self._stderr.println("changeLinkDisplay 1")
            self._stderr.println(e)
    
    def cbShowQueryString_clicked(self, e=None):
        """
        The event called when the "Show parameters as concatenated query string" checkbox is changed
        """
        self.setTabDefaultColor()

        # If the option was enabled and selected, unselect the Parameter "Show origin" option and then redisplay
        if self.cbShowQueryString.isEnabled():
            if self.cbShowQueryString.isSelected():
                self.cbShowParamOrigin.setSelected(False)
            self.changeParamDisplay()
        
    def btnHelp_clicked(self, e=None):
        """
        The event when the help icon is pressed. Try to display the Help page, but if the URL can't be reached, show a 404 message
        """
        self.setTabDefaultColor()
        jpane = JEditorPane()
        jpane.setEditable(False)
        try:
            # Workaround to display text correctly
            jpane2 = JEditorPane()
            jpane2.setPage(GAP_HELP_URL_BUTTON)
            text = jpane2.getText()
            jpane.setContentType("text/html")
            jpane.setText(text)
        except:
            jpane.setContentType("text/html")
            jpane.setText(GAP_HELP_404)
        jpane.setCaretPosition(0)
        jscroll = JScrollPane(jpane)
        jframe = JFrame("GAP Help")
        jframe.getContentPane().add(jscroll)
        jframe.setSize(800, 600)
        jframe.setLocationRelativeTo(None)
        # jframe.setResizable(False)
        jframe.setVisible(True)

        # Try to set the icon of the displayed pane
        try:
            imageUrl = URL(HELP_ICON)
            img = ImageIcon(imageUrl)
            jframe.setIconImage(img.getImage())
        except Exception as e:
            pass

    def btnChooseDir_clicked(self, e=None):
        """
        The event called when the "Choose..." directory button is clicked for the auto save path
        """
        self.setTabDefaultColor()
        # Show the directory choosing dialog box
        try:
            parentFrame = JFrame()
            dirChooser = JFileChooser()
            dirChooser.setDialogTitle("Choose GAP file output directory:")
            try:
                imageUrl = URL(DIR_ICON)
                img = ImageIcon(imageUrl)
                parentFrame.setIconImage(img.getImage())
            except:
                pass
            dirChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
            # Set the dialogs initial directory to the one displayed.
            try:
                dirChooser.setCurrentDirectory(File(self.inSaveDir.text))
            except:
                # If the displayed directory is no longer valid, start at the users home directory
                dirChooser.setCurrentDirectory(File("~"))
            userSelection = dirChooser.showOpenDialog(parentFrame)

            # Set the displayed save directory to the one selected
            if userSelection == JFileChooser.APPROVE_OPTION:
                self.inSaveDir.text = dirChooser.getSelectedFile().toString()

        except Exception as e:
            self._stderr.println("btnChooseDir_clicked 1")
            self._stderr.println(e)

    def setEnabledParamOptions(self, enabled):
        """
        Called when the "Parameters" check box is changed.
        It will enable/disable all options relating to Parameters.
        """
        # Enable/disable all Parameter options
        try:
            self.cbParamUrl.setEnabled(enabled)
            self.lblRequestParams.setEnabled(enabled)
            self.cbParamBody.setEnabled(enabled)
            self.cbParamMultiPart.setEnabled(enabled)
            self.cbParamJson.setEnabled(enabled)
            self.cbParamCookie.setEnabled(enabled)
            self.cbParamXml.setEnabled(enabled)
            self.cbParamXmlAttr.setEnabled(enabled)
            self.inQueryStringVal.setEnabled(enabled)
            self.cbReportSusParams.setEnabled(enabled)
            self.cbIncludePathWords.setEnabled(enabled)
            self.lblResponseParams.setEnabled(enabled)
            self.cbParamJSONResponse.setEnabled(enabled)
            self.cbParamXMLResponse.setEnabled(enabled)
            self.cbParamInputField.setEnabled(enabled)
            self.cbParamJSVars.setEnabled(enabled)
            if self.cbLinksEnabled.isSelected():
                self.cbParamFromLinks.setEnabled(enabled)
            else:
                self.cbParamFromLinks.setEnabled(False)
            if enabled and self.countParamUnique > 0:
                self.cbShowParamOrigin.setEnabled(True)
                self.cbShowSusParams.setEnabled(True)
                self.cbShowQueryString.setEnabled(True)
            else:
                self.cbShowParamOrigin.setEnabled(False)
                self.cbShowSusParams.setEnabled(False)
                self.cbShowQueryString.setEnabled(False)
        except Exception as e:
            self._stderr.println("setEnabledParamOptions 1")
            self._stderr.println(e)

    def setEnabledLinkOptions(self, enabled):
        """
        Called when the "Links" check box is changed.
        It will enable/disable all options relating to Links.
        """
        # Enable/disable all Link options
        try:
            self.cbSiteMapEndpoints.setEnabled(enabled)
            self.cbRelativeLinks.setEnabled(enabled)
            self.inExclusions.setEnabled(enabled)
            self.cbLinkPrefix.setEnabled(enabled)
            self.inLinkPrefix.setEnabled(enabled)
            self.cbLinkPrefixScope.setEnabled(enabled)
            if enabled:
                if self.cbLinkPrefix.isSelected() or self.cbLinkPrefixScope.isSelected():
                    self.cbUnPrefixed.setEnabled(True)
            else:
                 self.cbUnPrefixed.setEnabled(False)
            self.cbExclusions.setEnabled(enabled)
            self.inExclusions.setEnabled(enabled)
            if self.cbParamsEnabled.isSelected():
                self.cbParamFromLinks.setEnabled(enabled)
            else:
                self.cbParamFromLinks.setEnabled(False)
            if enabled and self.countLinkUnique > 0:
                self.cbShowLinkOrigin.setEnabled(True)
                self.cbInScopeOnly.setEnabled(True)
                self.btnFilter.setEnabled(True)
                self.lblLinkFilter.setEnabled(True)
                self.inLinkFilter.setEnabled(True)
                self.cbLinkFilterNeg.setEnabled(True)
                self.cbLinkCaseSens.setEnabled(True)
            else:
                self.cbShowLinkOrigin.setEnabled(False)
                self.cbInScopeOnly.setEnabled(False)
                self.btnFilter.setEnabled(False)
                self.lblLinkFilter.setEnabled(False)
                self.inLinkFilter.setEnabled(False)
                self.cbLinkFilterNeg.setEnabled(False)
                self.cbLinkCaseSens.setEnabled(False)
        except Exception as e:
            self._stderr.println("setEnabledLinkOptions 1")
            self._stderr.println(e)

    def setEnabledWordOptions(self, enabled):
        """
        Called when the "Words" check box is changed.
        It will enable/disable all options relating to Words.
        """
        # Enable/disable all Words options
        try:
            self.cbWordParams.setEnabled(enabled)
            self.cbWordComments.setEnabled(enabled)
            self.cbWordDigits.setEnabled(enabled)
            self.cbWordImgAlt.setEnabled(enabled)
            self.cbWordLower.setEnabled(enabled)
            self.cbWordPaths.setEnabled(enabled)
            self.cbWordPlurals.setEnabled(enabled)
            self.lblWordsMaxLen.setEnabled(enabled)
            self.lblWordsMaxLen2.setEnabled(enabled)
            self.inWordsMaxlen.setEnabled(enabled)
            self.lblStopWords.setEnabled(enabled)
            self.inStopWords.setEnabled(enabled)
            if enabled and self.countWordUnique > 0:
                self.cbShowWordOrigin.setEnabled(True)
            else:
                self.cbShowWordOrigin.setEnabled(False)
        except Exception as e:
            self._stderr.println("setEnabledWordOptions 1")
            self._stderr.println(e)
            
    def setEnabledAll(self, enable):
        """
        Called when the GAP process starts to stop the user changing any options during a run, and then re-enabled after a run is complete
        """
        if _debug:
            print("setEnabledAll started")
        try:
            self.cbLinksEnabled.setEnabled(enable)
            self.cbParamsEnabled.setEnabled(enable)
            self.cbWordsEnabled.setEnabled(enable)
            if self.cbParamsEnabled.isSelected():
                self.setEnabledParamOptions(enable)
            if self.cbLinksEnabled.isSelected():
                self.setEnabledLinkOptions(enable)
            if self.cbWordsEnabled.isSelected():
                self.setEnabledWordOptions(enable)
            self.btnRestoreDefaults.setEnabled(enable)
            self.cbSaveFile.setEnabled(enable)
            self.inSaveDir.setEnabled(enable)
            self.btnChooseDir.setEnabled(enable)
            self.btnSave.setEnabled(enable)
            self.cbToolTips.setEnabled(enable)
        except Exception as e:
            self._stderr.println("setEnabledAll 1")
            self._stderr.println(e)

    def btnFilter_clicked(self, e=None):
        """
        The event called when the "Apply/Clear filter" button is clicked
        """
        if _debug:
            print("btnFilter_clicked started")
        self.setTabDefaultColor()
        if self.btnFilter.text == "Apply filter":

            # Clear the current link list and filtered list
            self.outLinkList.text = ""
            self.txtLinksFiltered = ""

            # Determine which text to process
            if self.cbShowLinkOrigin.isSelected():
                if self.cbInScopeOnly.isSelected():
                    txtToProcess = self.txtLinksWithURLInScopeOnly
                else:
                    txtToProcess = self.txtLinksWithURL
            else:
                if self.cbInScopeOnly.isSelected():
                    txtToProcess = self.txtLinksOnlyInScopeOnly
                else:
                    txtToProcess = self.txtLinksOnly

            # Build up the set of links to display
            try:
                # Go through all the lines in the Link text with origin URLs
                for line in txtToProcess.splitlines():
                    # If the Negative match option is selected then...
                    if self.cbLinkFilterNeg.isSelected():
                        # add the line if it does contain the entered filter text
                        if (
                            self.cbLinkCaseSens.isSelected()
                            and not self.inLinkFilter.text in line
                        ) or (
                            not self.cbLinkCaseSens.isSelected()
                            and not self.inLinkFilter.text.lower() in line.lower()
                        ):
                            self.txtLinksFiltered = self.txtLinksFiltered + line + "\n"
                    else:  # else look for positive match and
                        # add the line if it doesn't contain the entered filter text
                        if (
                            self.cbLinkCaseSens.isSelected()
                            and self.inLinkFilter.text in line
                        ) or (
                            not self.cbLinkCaseSens.isSelected()
                            and self.inLinkFilter.text.lower() in line.lower()
                        ):
                            self.txtLinksFiltered = self.txtLinksFiltered + line + "\n"

            except Exception as e:
                self._stderr.println("btnFilter_clicked 1")
                self._stderr.println(e)

            # Set the link list to the filtered text
            try:
                if self.txtLinksFiltered != "":
                    self.outLinkList.text = self.txtLinksFiltered
                else:
                    self.outLinkList.text = "NO FILTERED LINKS FOUND"
            except Exception as e:
                self._stderr.println("btnFilter_clicked 2")
                self._stderr.println(e)

            # Set the label to show number of filtered links
            self.lblLinkList.text = (
                "Potential links found - "
                + str(self.outLinkList.text.count("\n"))
                + " filtered:"
            )

            # Once the Apply Filter has been pressed it is changed to Clear filter
            self.btnFilter.setText("Clear filter")

        else:  # the buttons caption is "Clear filter"

            try:
                # Clear the filter
                self.inLinkFilter.text = ""
                self.txtLinksFiltered = ""

                # Reset the Link text area depending on the filters selected
                if self.cbShowLinkOrigin.isSelected():
                    if self.cbInScopeOnly.isSelected():
                        self.outLinkList.text = self.txtLinksWithURLInScopeOnly
                    else:
                        self.outLinkList.text = self.txtLinksWithURL
                else:
                    if self.cbInScopeOnly.isSelected():
                        self.outLinkList.text = self.txtLinksOnlyInScopeOnly
                    else:
                        self.outLinkList.text = self.txtLinksOnly

                # Display the number of unique or filtered links, depending on the filters in place
                if str(self.countLinkUnique) == str(self.outLinkList.text.count("\n")):
                    self.lblLinkList.text = (
                        "Potential links found - "
                        + str(self.countLinkUnique)
                        + " unique:"
                    )
                else:
                    self.lblLinkList.text = (
                        "Potential links found - "
                        + str(self.outLinkList.text.count("\n"))
                        + " filtered:"
                    )

                # Change the label back to "Apply filter" and disable the button
                self.btnFilter.setText("Apply filter")
                self.btnFilter.setEnabled(False)

            except Exception as e:
                self._stderr.println("btnFilter_clicked 3")
                self._stderr.println(e)

        # Position the links output at the start again
        self.outLinkList.setCaretPosition(0)
                
    def btnSave_clicked(self, e=None):
        """
        The event called when the "Save options" button is clicked
        """
        self.setTabDefaultColor()
        self.saveConfig()

    def cbLinkPrefixScope_clicked(self, e=None):
        """
        The event called when the "use selected target(s)" checkbox is changed
        """
        self.setTabDefaultColor()
        # Only enable the Link Prefix field and Un_Prefixed checkbox if the Link Prefix checkbox is selected
        if self.cbLinkPrefixScope.isSelected():
            self.cbUnPrefixed.setEnabled(True)
        else:
            if not self.cbLinkPrefix.isSelected():
                self.cbUnPrefixed.setEnabled(False)
            
    def checkLinkPrefix(self, e=None):
        """
        Check the Link Prefix is a valid URL
        """
        try:
            invalid = False
            self.inLinkPrefix.text = self.inLinkPrefix.text.strip()
            
            # If the last character is a ; then strip it
            if self.inLinkPrefix.text.endswith(";"):
                self.inLinkPrefix.text = self.inLinkPrefix.text[:-1]
            
            # Check if the links are valid    
            if self.cbLinkPrefix.isSelected():
                fixedLinks = ""
                for link in self.inLinkPrefix.text.split(";"):
                    # If the last character is a / then strip it
                    if link.endswith("/"):
                        link = link[:-1]
                    result = urlparse(link)
                    if result.netloc == "":
                        # If prefix doesn't start with // then add http://
                        if result.scheme == "" and link[:2] != "//":
                            link = "http://" + link
                    if fixedLinks == "":
                        fixedLinks = link
                    else:
                        fixedLinks = fixedLinks + ";" + link
                    if re.search(r'^https?:\/\/([-a-z0-9@:%._\+~#=]{1,256}\.)+[a-z0-9]{2,6}$', link, flags=re.IGNORECASE) is None:
                        invalid = True
                if not invalid:
                    self.inLinkPrefix.text = fixedLinks
                
            # Set visibility of warning
            if self.linkPrefixColor is None:
                self.linkPrefixColor = self.inLinkPrefix.getForeground()
            if invalid:
                self.inLinkPrefix.setForeground(Color.RED)
            else:
                if self.linkPrefixColor is not None:
                    self.inLinkPrefix.setForeground(self.linkPrefixColor)
        except Exception as e:
            self._stderr.println("checkLinkPrefix 1")
            self._stderr.println(e)
            
    def checkMaxWordsLen(self):
        """
        Check the Max Words Length field and change if necessary
        """
        
        # If the maximum word length isn't a number, then set back to default
        if not self.inWordsMaxlen.text.isdigit():
            self.inWordsMaxlen.text = DEFAULT_MAX_WORD_LEN
        else:
            # else if it is a number, but less that 3, set it to 3
            try:
                if int(self.inWordsMaxlen.text) < 3:
                    self.inWordsMaxlen.text = "3"
            except:
                self.inWordsMaxlen.text = DEFAULT_MAX_WORD_LEN
                
    def saveConfig(self):
        """
        Save the options selected to the config
        """
        # Save the autosave output directory used, IF it is real directory
        try:
            # If its a real directory, the following line will not fail
            listOfFile = os.listdir(self.inSaveDir.text)
            # Leave the value as it is
        except:
            # It wasn't a real directory, so set it back to Home directory
            self.inSaveDir.text = self.getDefaultSaveDirectory()

        # Check the words max length in case we need to change it first
        self.checkMaxWordsLen()
        
        # Check the link prefix if option selected
        if self.cbLinkPrefix.isSelected():
            self.checkLinkPrefix()
                 
        # Save the config
        try:
            config = {
                "saveFile": self.cbSaveFile.isSelected(),
                "paramUrl": self.cbParamUrl.isSelected(),
                "paramBody": self.cbParamBody.isSelected(),
                "paramMultiPart": self.cbParamMultiPart.isSelected(),
                "paramJson": self.cbParamJson.isSelected(),
                "paramCookie": self.cbParamCookie.isSelected(),
                "paramXml": self.cbParamXml.isSelected(),
                "paramXmlAttr": self.cbParamXmlAttr.isSelected(),
                "reportSusParams": self.cbReportSusParams.isSelected(),
                "includePathWords": self.cbIncludePathWords.isSelected(),
                "paramJsonResponse": self.cbParamJSONResponse.isSelected(),
                "paramXmlResponse": self.cbParamXMLResponse.isSelected(),
                "paramInputField": self.cbParamInputField.isSelected(),
                "paramJSVars": self.cbParamJSVars.isSelected(),
                "saveDir": self.inSaveDir.text,
                "paramFromLinks": self.cbParamFromLinks.isSelected(),
                "exclusionsEnabled": self.cbExclusions.isSelected(),
                "linkExclusions": self.inExclusions.text,
                "showParamOrigin": self.cbShowParamOrigin.isSelected(),
                "showLinkOrigin": self.cbShowLinkOrigin.isSelected(),
                "showWordOrigin": self.cbShowWordOrigin.isSelected(),
                "inScopeOnly": self.cbInScopeOnly.isSelected(),
                "sitemapEndpoints": self.cbSiteMapEndpoints.isSelected(),
                "relativeLinks": self.cbRelativeLinks.isSelected(),
                "paramsEnabled": self.cbParamsEnabled.isSelected(),
                "linksEnabled": self.cbLinksEnabled.isSelected(),
                "linkPrefixChecked": self.cbLinkPrefix.isSelected(),
                "linkPrefix": self.inLinkPrefix.text,
                "linkPrefixScopeChecked": self.cbLinkPrefixScope.isSelected(),
                "unprefixed": self.cbUnPrefixed.isSelected(),
                "wordsEnabled": self.cbWordsEnabled.isSelected(),
                "wordPlurals": self.cbWordPlurals.isSelected(),
                "wordPaths": self.cbWordPaths.isSelected(),
                "wordParams": self.cbWordParams.isSelected(),
                "wordDigits": self.cbWordDigits.isSelected(),
                "wordComments": self.cbWordComments.isSelected(),
                "wordImgAlt": self.cbWordImgAlt.isSelected(),
                "wordLower": self.cbWordLower.isSelected(),
                "wordMaxLen": self.inWordsMaxlen.text,
                "stopWords": self.inStopWords.text,
                "tooltips": self.cbToolTips.isSelected()          
            }
            self._callbacks.saveExtensionSetting("config", pickle.dumps(config))
        except Exception as e:
            self._stderr.println("saveConfig 1")
            self._stderr.println(e)
            
    def restoreSavedConfig(self):
        """
        Loads the saved config options
        """
        # Get saved config
        storedConfig = self._callbacks.loadExtensionSetting("config")
        if storedConfig != None:
            try:
                config = pickle.loads(storedConfig)
                try:
                    self.cbSaveFile.setSelected(config["saveFile"])
                except:
                    self.cbSaveFile.setSelected(True)
                try:
                    self.cbParamUrl.setSelected(config["paramUrl"])
                except:
                    self.cbParamUrl.setSelected(False)
                try:
                    self.cbParamBody.setSelected(config["paramBody"])
                except:
                    self.cbParamBody.setSelected(False)
                try:
                    self.cbParamMultiPart.setSelected(config["paramMultiPart"])
                except:
                    self.cbParamMultiPart.setSelected(True)
                try:
                    self.cbParamJson.setSelected(config["paramJson"])
                except:
                    self.cbParamJson.setSelected(False)
                try:
                    self.cbParamCookie.setSelected(config["paramCookie"])
                except:
                    self.cbParamCookie.setSelected(False)
                try:
                    self.cbParamXml.setSelected(config["paramXml"])
                except:
                    self.cbParamXml.setSelected(False)
                try:
                    self.cbParamXmlAttr.setSelected(config["paramXmlAttr"])
                except:
                    self.cbParamXmlAttr.setSelected(False)
                self.cbShowSusParams.setSelected(False)
                self.cbShowQueryString.setSelected(False)
                try:
                    self.inQueryStringVal.text = config["queryStringVal"]
                except:
                    self.inQueryStringVal.text = DEFAULT_QSV
                try:
                    self.cbReportSusParams.setSelected(config["reportSusParams"])
                except:
                    self.cbReportSusParams.setSelected(True)
                try:
                    self.cbIncludePathWords.setSelected(config["includePathWords"])
                except:
                    self.cbIncludePathWords.setSelected(False)
                try:
                    self.cbParamJSONResponse.setSelected(config["paramJsonResponse"])
                except:
                    self.cbParamJSONResponse.setSelected(False)
                try:
                    self.cbParamXMLResponse.setSelected(config["paramXmlResponse"])
                except:
                    self.cbParamXMLResponse.setSelected(False)
                try:
                    self.cbParamInputField.setSelected(config["paramInputField"])
                except:
                    self.cbParamInputField.setSelected(False)
                try:
                    self.cbParamJSVars.setSelected(config["paramJSVars"])
                except:
                    self.cbParamJSVars.setSelected(False)
                try:
                    self.inSaveDir.text = config["saveDir"]
                    # Check the directory is valid, otherwise an error will be raised and it will be reset to default
                    listOfFile = os.listdir(self.inSaveDir.text)
                except:
                    self.inSaveDir.text = self.getDefaultSaveDirectory()
                try:
                    self.cbParamFromLinks.setSelected(config["paramFromLinks"])
                except:
                    self.cbParamFromLinks.setSelected(False)
                try:
                    self.cbExclusions.setSelected(config["exclusionsEnabled"])
                except:
                    self.cbExclusions.setSelected(True)
                try:
                    self.inExclusions.text = config["linkExclusions"]
                except:
                    self.inExclusions.text = DEFAULT_EXCLUSIONS
                try:
                    self.cbShowParamOrigin.setSelected(config["showParamOrigin"])
                except:
                    self.cbShowParamOrigin.setSelected(False)
                try:
                    self.cbShowLinkOrigin.setSelected(config["showLinkOrigin"])
                except:
                    self.cbShowLinkOrigin.setSelected(False)
                try:
                    self.cbShowWordOrigin.setSelected(config["showWordOrigin"])
                except:
                    self.cbShowWordOrigin.setSelected(False)
                try:
                    self.cbInScopeOnly.setSelected(config["inScopeOnly"])
                except:
                    self.cbInScopeOnly.setSelected(True)
                try:
                    self.cbSiteMapEndpoints.setSelected(config["sitemapEndpoints"])
                except:
                    self.cbSiteMapEndpoints.setSelected(False)
                try:
                    self.cbRelativeLinks.setSelected(config["relativeLinks"])
                except:
                    self.cbRelativeLinks.setSelected(True)
                try:
                    self.cbParamsEnabled.setSelected(config["paramsEnabled"])
                except:
                    self.cbParamsEnabled.setSelected(True)
                try:
                    self.cbLinksEnabled.setSelected(config["linksEnabled"])
                except:
                    self.cbLinksEnabled.setSelected(True)
                try:
                    self.cbLinkPrefix.setSelected(config["linkPrefixChecked"])
                except:
                    self.cbLinkPrefix.setSelected(False)
                try:
                    self.inLinkPrefix.text = config["linkPrefix"]
                except:
                    self.inLinkPrefix.text = DEFAULT_LINK_PREFIX
                try:
                    self.cbLinkPrefixScope.setSelected(config["linkPrefixScopeChecked"])
                except:
                    self.cbLinkPrefixScope.setSelected(False)
                try:
                    self.cbUnPrefixed.setSelected(config["unprefixed"])
                except:
                    self.cbUnPrefixed.setSelected(False)
                try:
                    self.cbWordsEnabled.setSelected(config["wordsEnabled"])
                except:
                    self.cbWordsEnabled.setSelected(True)
                try:
                    self.cbWordPlurals.setSelected(config["wordPlurals"])
                except:
                    self.cbWordPlurals.setSelected(True)
                try:
                    self.cbWordPaths.setSelected(config["wordPaths"])
                except:
                    self.cbWordPaths.setSelected(False)
                try:
                    self.cbWordDigits.setSelected(config["wordDigits"])
                except:
                    self.cbWordDigits.setSelected(True)
                try:
                    self.cbWordParams.setSelected(config["wordParams"])
                except:
                    self.cbWordParams.setSelected(False)
                try:
                    self.cbWordComments.setSelected(config["wordComments"])
                except:
                    self.cbWordComments.setSelected(True)
                try:
                    self.cbWordImgAlt.setSelected(config["wordImgAlt"])
                except:
                    self.cbWordImgAlt.setSelected(True)
                try:
                    self.cbWordImgAlt.setSelected(config["wordLower"])
                except:
                    self.cbWordImgAlt.setSelected(True)
                try:
                    self.inWordsMaxlen.text = (config["wordMaxLen"])
                except:
                    self.inWordsMaxlen.text = DEFAULT_MAX_WORD_LEN
                try:
                    self.inStopWords.text = (config["stopWords"])
                except:
                    self.inStopWords.text = DEFAULT_STOP_WORDS
                try:
                    self.cbToolTips.setSelected(config["tooltips"])
                except:
                    self.cbToolTips.setSelected(True)
                # Check the words max length in case we need to change it first
                self.checkMaxWordsLen()
                # Check the link prefix is a valid url
                self.checkLinkPrefix()
            except Exception as e:
                # An error will occur the first time used if no settings have been saved.
                # The default settings will be used instead
                pass
        
            # if the link exclusions setting doesn't exist, set it to default
            if self.inExclusions.text == "":
                self.inExclusions.text = DEFAULT_EXCLUSIONS
            
            # If the query string param value doesn't exist, set it to the default
            if self.inQueryStringVal.text == "":
                self.inQueryStringVal.text = DEFAULT_QSV
            
            # if the stop words setting doesn't exist, set it to default
            if self.inStopWords.text == "":
                self.inStopWords.text = DEFAULT_STOP_WORDS
        
        else:
            # If config doesn't exist then restore defaults
            self.btnRestoreDefaults_clicked()
            
            
    def btnRestoreDefaults_clicked(self, e=None):
        """
        The event called when the "Restore defaults" button is clicked.
        Restore the default config options
        """
        self.setTabDefaultColor()
        
        # Re-enable all Param options
        self.setEnabledParamOptions(True)

        # Re-enable all Link options
        self.setEnabledLinkOptions(True)
        
        # Re-enable all Word options
        self.setEnabledWordOptions(True)

        # Reset config values
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
        self.cbShowSusParams.setSelected(False)
        self.cbShowQueryString.setSelected(False)
        self.inQueryStringVal.text = DEFAULT_QSV
        self.cbReportSusParams.setSelected(True)
        self.cbIncludePathWords.setSelected(False)
        self.cbParamJSVars.setSelected(False)
        self.inSaveDir.text = self.getDefaultSaveDirectory()
        self.cbParamFromLinks.setSelected(False)
        self.inExclusions.text = DEFAULT_EXCLUSIONS
        self.cbShowParamOrigin.setSelected(False)
        self.cbShowLinkOrigin.setSelected(False)
        self.cbShowWordOrigin.setSelected(False)
        self.cbInScopeOnly.setSelected(False)
        self.cbSiteMapEndpoints.setSelected(False)
        self.cbRelativeLinks.setSelected(True)
        self.cbParamsEnabled.setSelected(True)
        self.cbLinksEnabled.setSelected(True)
        self.cbLinkPrefix.setSelected(False)
        self.cbUnPrefixed.setSelected(False)
        self.inLinkPrefix.text = DEFAULT_LINK_PREFIX
        self.cbLinkPrefixScope.setSelected(False)
        self.cbWordsEnabled.setSelected(True)
        self.cbWordPlurals.setSelected(True)
        self.cbWordPaths.setSelected(False)
        self.cbWordParams.setSelected(False)
        self.cbWordComments.setSelected(True)
        self.cbWordImgAlt.setSelected(True)
        self.cbWordLower.setSelected(True)
        self.cbWordDigits.setSelected(True)
        self.inWordsMaxlen.text = DEFAULT_MAX_WORD_LEN
        self.inStopWords.text = DEFAULT_STOP_WORDS
        self.saveConfig

    def createMenuItems(self, context):
        """
        Invokes the Extensions "GAP" menu.
        """
        self.context = context
        menuList = ArrayList()
        menuGAP = JMenuItem("GAP", actionPerformed=self.menuGAP_clicked)
        menuList.add(menuGAP)
        return menuList

    def menuGAP_clicked(self, e=None):
        """
        The event called when the Extensions -> GAP option is selected
        """
        if _debug:
            print("menuGAP_clicked started")
        self.setTabDefaultColor()
        try:
            # Check the words max length in case we need to change it first
            self.checkMaxWordsLen()
            
            # Check the link prefix is valid
            self.checkLinkPrefix()
        
            # If the user has run GAP, but it is already running then cancel the previous run
            if not self.flagCANCEL and self.btnCancel.text.find("CANCEL GAP") >= 0:
                self.btnCancel_clicked()
            # If the previous run is currently being cancelled, then wait until is had completely ended
            waiting = 0
            while self.flagCANCEL:
                waiting = waiting + 1
                time.sleep(0.2)
                # If 10 seconds has passed then just break and start the new run
                if waiting == 50:
                    break

            # Initialize
            self.roots.clear()
            self.param_list.clear()
            self.paramUrl_list.clear()
            self.paramSus_list.clear()
            self.paramSusUrl_list.clear()
            self.susParamText.clear()
            self.susParamIssue.clear()
            self.txtParamsOnly = ""
            self.txtParamsWithURL = ""
            self.txtParamsSusOnly = ""
            self.txtParamsSusWithURL = ""
            self.txtParamsQuery = ""
            self.txtParamQuery = ""
            self.txtParamQuerySus = ""
            self.link_list.clear()
            self.linkInScope_list.clear()
            self.linkUrl_list.clear()
            self.linkUrlInScope_list.clear()
            self.word_list.clear()
            self.wordUrl_list.clear()
            self.txtLinksOnly = ""
            self.txtLinksWithURL = ""
            self.txtLinksOnlyInScopeOnly = ""
            self.txtLinksWithURLInScopeOnly = ""
            self.inLinkFilter.text = ""
            self.btnFilter.text = "Apply filter"
            self.allScopePrefixes.clear()
            
            # Disable all fields so user can't make changes during a run
            self.setEnabledAll(False)

            # Show the CANCEL button
            self.flagCANCEL = False
            self.btnCancel.setText("   CANCEL GAP   ")
            self.btnCancel.setVisible(True)
            self.btnCancel.setEnabled(True)
            self.progStage.setVisible(False)
            self.progBar.setVisible(False)
            
            # Before starting the search, update the text boxes depending on the options selected
            if self.cbParamsEnabled.isSelected():
                self.lblParamList.text = "Potential params found - SEARCHING"
                self.outParamList.text = "SEARCHING..."
            else:
                self.lblParamList.text = "Potential params found:"
                self.outParamList.text = ""
            if self.cbLinksEnabled.isSelected():
                self.lblLinkList.text = "Potential links found - SEARCHING"
                self.outLinkList.text = "SEARCHING..."
            else:
                self.lblLinkList.text = "Potential links found:"
                self.outLinkList.text = ""
            if WORDLIST_IMPORT_ERROR != "":
                self.lblWordList.text = "Words found - UNAVAILABLE:"
                self.outWordList.text = WORDLIST_IMPORT_ERROR
            else:
                if self.cbWordsEnabled.isSelected():
                    self.lblWordList.text = "Words found - SEARCHING"
                    self.outWordList.text = "SEARCHING..."
                else:
                    self.lblWordList.text = "Words found:"
                    self.outWordList.text = ""

            # Run everything in a thread so it doesn't freeze Burp while it gets everything
            if _debug:
                t = threading.Thread(target=self.doEverythingProfile, args=[])
            else:
                t = threading.Thread(target=self.doEverything, args=[])
            t.daemon = True
            t.start()
            if _debug:
                print("menuGAP_clicked thread started")

            # Clean up
            self.roots.clear()
            
        except Exception as e:
            self._stderr.println("menuGAP_clicked 1")
            self._stderr.println(e)

    def getSiteMapLinks(self):
        """
        Add site map links if required
        """
        try:
            self.txtDebugDetail.text = "getSiteMapLinks"
            if _debug:
                print("getSiteMapLinks started")

            url = self.currentReqResp.getRequestUrl()
            urlNoQS = url
            if urlNoQS.find("?") >= 0:
                urlNoQS = urlNoQS[0 : urlNoQS.find("?")]
            if len(url) > 0:

                # Check link against list of exclusions
                 if self.includeLink(url):
                        
                    if self.currentReqResp.isResponse():
                        
                        # If it is content-type we want to process then carry on
                        if self.currentContentTypeInclude:

                            # Only process links that are in scope
                            if self.isLinkInScope(url):
                                self.addLink(url,urlNoQS)
                    else:
                        # It could be a request in the site map that hasn't been requested yet
                        # Only process links that are in scope
                        if self.isLinkInScope(url):
                            self.addLink(url,urlNoQS)

        except Exception as e:
            self._stderr.println("getSiteMapLinks 1")
            self._stderr.println(e)

    def getTabIndex(self):
        """
        Get the Index of the GAP tab
        """
        try:
            tabIndex = 0
            try:
                while tabIndex < self.parentTabbedPane.getTabCount():
                    if self.parentTabbedPane.getTitleAt(tabIndex).startswith("GAP"):
                        break
                    tabIndex = tabIndex + 1
                return tabIndex
            except:
                return -1
        except Exception as e:
            self._stderr.println("getTabColor 1")
            self._stderr.println(e)
    
    def getTabColor(self):
        """
        Get the color of the GAP Tab title
        """
        try:
            if self.parentTabbedPane is None:
                self.parentTabbedPane = self.getUiComponent().getParent()
            if self.parentTabbedPane is not None:
                tabIndex = self.getTabIndex()  
                if tabIndex >= 0:              
                    return self.parentTabbedPane.getForegroundAt(tabIndex)
        except Exception as e:
            self._stderr.println("getTabColor 1")
            self._stderr.println(e)
    
    def setTabDefaultColor(self):
        """
        Change the color of the GAP Tab to the default color
        """
        try:
            self.setTabColor(self.tabDefaultColor)
        except:
            pass
        
    def setTabColor(self, color):
        """
        Change the color of the GAP Tab title
        """
        try:
            if self.parentTabbedPane is None:
                self.parentTabbedPane = self.getUiComponent().getParent()
            if self.parentTabbedPane is not None:
                tabIndex = self.getTabIndex()  
                if tabIndex >= 0:              
                    self.parentTabbedPane.setBackgroundAt(tabIndex, color)
        except Exception as e:
            pass
    
    def setTabTitle(self, title):
        """
        Change the color of the GAP Tab title
        """
        try:
            if self.parentTabbedPane is None:
                self.parentTabbedPane = self.getUiComponent().getParent()
            if self.parentTabbedPane is not None:
                tabIndex = self.getTabIndex()  
                if tabIndex >= 0:              
                    self.parentTabbedPane.setTitleAt(tabIndex, title)
                else:
                    self.parentTabbedPane.setTitleAt(tabIndex, "GAP")
        except Exception as e:
            self._stderr.println("setTabTitle 1")
            self._stderr.println(e)
    
    def removeStdPort(self, url):
        """
        If a Url is http, then remove port :80 as this isn't needed
        If a Url is https, then remove port :443 as this isn't needed
        """
        self.txtDebugDetail.text = "removeStdPort: "+url
        try:
            if url.find(":443") > 0:
                if url.startswith("https:") and self.REGEX_PORT443.search(url) is not None:
                    url = self.REGEX_PORTSUB443.sub("", url, 1)
            elif url.find(":80") > 0:
                if url.startswith("http:") and self.REGEX_PORT80.search(url) is not None:
                    url = self.REGEX_PORTSUB80.sub("", url, 1)
        except Exception as e:
            self._stderr.println("removeStdPort 1")
            self._stderr.println(e)
        return url
    
    def processMessage(self):

        try:
            if _debug or self.txtDebug.isVisible():
                url = self.currentReqResp.getRequestUrl().encode("UTF-8")
                self.txtDebug.text = "Processing: "+url
                if _debug:
                    print("Current request: "+ url)
                
            # Check if contentType is included to use at various stages later
            if self.currentReqResp.getResponseContentType() != "":
                self.currentContentTypeInclude = self.includeContentType()
            else:
                self.currentContentTypeInclude = False
            
            # If Parameters are enabled
            if self.cbParamsEnabled.isSelected():

                # If there is a request, get parameters that Burp has identified
                if self.currentReqResp.isRequest():
                    self.getBurpParams()
                    self.getRequestParams()

                # Get parameters from the response
                if self.currentReqResp.isResponse():
                    self.getResponseParams()
                        
            # Get path words if requested and URL is in scope
            # Only get if there is a response. This is because Burp will put links in the sitemap that haven't been requested, but can incorrectly get links with wrong paths that then end up with words that make no sense
            if ((self.cbParamsEnabled.isSelected() and self.cbIncludePathWords.isSelected()) or (self.cbWordsEnabled.isSelected() and self.cbWordPaths.isSelected())) and self.isLinkInScope(self.currentReqResp.getRequestUrl()) and self.currentReqResp.isResponse():
                self.getPathWords()
            
            # If there is a response
            if self.currentReqResp.isResponse():
                
                # If Links are enabled, get all the links for the current endpoint
                if self.cbLinksEnabled.isSelected():
                    self.getResponseLinks()
                    
                # If the words mode is enabled then search response for words
                if self.cbWordsEnabled.isSelected():
                    self.getResponseWords()
                    
        except Exception as e:
            self._stderr.println("processMessage 1")
            self._stderr.println(e)
            
    def doEverythingProfile(self):
        """
        Used for debugging purposes
        """
        try:
            pr = profile.Profile()
            pr.runctx("self.doEverything()",globals(),locals())

            stats = pstats.Stats(pr)
            stats.print_stats()

        except Exception as e:
            self._stderr.println("doEverythingProfile")
            self._stderr.println(e)
    
           
    def doEverything(self):
        """
        The methods run in a separate thread when the GAP menu item has been clicked.
        Obtains the selected messages from the interface. Filters the sitemap for all messages containing
        URLs within the selected messages' hierarchy. If so, the message is analyzed to create a parameter list.
        """    
        if _debug:
            print("doEverything started")
        
        self.setTabTitle("GAP*")
        
        # Get the parentTab if it hasn't been set yet
        if self.parentTabbedPane is None:
            self.parentTabbedPane = self.getUiComponent().getParent()
            # Also get the default color of the tab text
            self.tabDefaultColor = self.getTabColor()
        else:
            # Set the tab to the default color
            self.setTabDefaultColor()
        
        # Change the Progress bar
        self.progBar.setValue(0)
        self.progBar.setMaximum(0)
        self.progBar.setString("Starting...")
        self.progBar.setVisible(True)
        
        # Ensure the full list of parameters are shown first
        self.cbShowSusParams.setSelected(False)
        
        # Get all first-level selected messages and store the URLs as roots to filter the sitemap
        try:
            self.txtDebug.text = "Getting selected messages..."
            allMessages = self.context.getSelectedMessages()
            
            # If the Site Map Tree was the context for GAP, then get the Site Map instead of the selected messages
            # because in that case it only takes the root
            if self.context.getInvocationContext() == 4:
                
                for http_message in allMessages:
                    if http_message.getUrl() is not None:
                        # Need to strip the port from the URL before searching because it _callbacks.getSiteMap fails with older versions of Burp if you don't
                        target = self.REGEX_PORTSUB.sub("", http_message.getUrl().toString())
                        self.roots.add(target)
                    self.checkIfCancel()

                # If specified to prefix using targets, then get all roots for prefixing
                if self.cbLinkPrefixScope.isSelected():
                    for root in self.roots:
                        prefix = urlparse(root).scheme + "://" + urlparse(root).netloc
                        self.allScopePrefixes.add(prefix)
                                
                # Get all sitemap entries associated with the selected messages and scrape them for parameters, links and words
                currentRoot = 0
                totalRoots = len(self.roots)
                for root in self.roots:
                    self.checkIfCancel()
                    
                    # Change the Progress Stage 
                    currentRoot = currentRoot + 1
                    if totalRoots > 1:
                        self.progStage.text = str(currentRoot) + " / " + str(totalRoots)
                        self.progStage.setVisible(True)
                    else:
                        self.progStage.setVisible(False)
                    self.progBar.setValue(0)
                    self.progBar.setString("Getting reqs...")
                    
                    # Get all the messages for the current root
                    self.txtDebug.text = "Getting messages for root: "+root
                    self.txtDebugDetail.text = ""
                    allMessages = self._callbacks.getSiteMap(root)
                                    
                    # Change the Progress bar
                    noOfMsgs = len(allMessages)
                    self.progBar.setMaximum(noOfMsgs)
                    if self.cbToolTips.isSelected():
                        self.progStage.setToolTipText("What Site Map target is being processed out of the total number of targets selected.\nCurrent target: " + root)         
                    self.progBar.setString("0/" + str(noOfMsgs))
                    
                    index = 0
                    for http_message in allMessages:
                        index = index + 1
                        self.progBar.setValue(index)
                        self.progBar.setString(str(index) + "/" + str(noOfMsgs))
                        self.checkIfCancel()

                        # Only process if the request is in scope
                        if self._callbacks.isInScope(http_message.getUrl()):
                            
                            # Get the current request/response details
                            self.currentReqResp = ReqResp(http_message, self._helpers, self._stderr)
                            
                            if self.currentReqResp.isRequest():

                                # Get the links from the site map if the option is selected
                                if self.cbLinksEnabled.isSelected() and self.cbSiteMapEndpoints.isSelected():
                                    self.getSiteMapLinks()

                                # will scrape the same URL multiple times if the site map has stored multiple instances
                                # the site map stores multiple instances if it detects differences, so this is desirable
                                rooturl = urlparse(root)
                                responseurl = urlparse(self.currentReqResp.getRequestUrl())
                                if rooturl.hostname == responseurl.hostname:

                                    # Process the message if in scope
                                    self.processMessage()
                                    
                            self.currentReqResp = None
                            
            else:
                
                # Change the Progress bar
                noOfMsgs = len(allMessages)
                self.progBar.setValue(0)
                self.progBar.setMaximum(noOfMsgs)
                self.progStage.setVisible(False)
                self.progBar.setString("0/" + str(noOfMsgs))
  
                index = 0
                for http_message in allMessages:
                    index = index + 1
                    self.progBar.setValue(index)
                    self.progBar.setString(str(index) + "/" + str(noOfMsgs))
                    self.checkIfCancel()
                    
                    # Get the current request/response details
                    self.currentReqResp = ReqResp(http_message, self._helpers, self._stderr)
                    root = self.currentReqResp.getRequestUrl()
                    self.roots.add(root)
                    prefix = urlparse(root).scheme + "://" + urlparse(root).netloc
                    self.allScopePrefixes.add(prefix)
                    
                    if self.currentReqResp.isRequest():
                        
                        # Get the links from the site map if the option is selected
                        if self.cbLinksEnabled.isSelected() and self.cbSiteMapEndpoints.isSelected():
                            self.getSiteMapLinks()
                            
                        # Process the message
                        self.processMessage()
                    
                    self.currentReqResp = None
                        
            # Change the Progress bar
            self.progBar.setValue(0)
            maxValue = 0
            if self.cbParamsEnabled.isSelected():
                maxValue = maxValue + 1
            if self.cbLinksEnabled.isSelected():
                maxValue = maxValue + 1
            if self.cbWordsEnabled.isSelected():
                maxValue = maxValue + 1
            self.progBar.setMaximum(maxValue)
            self.progBar.setString("Processing...")
            
            # Display the parameters and links that are found
            self.checkIfCancel()
            self.displayResults()

            # Change button to completed
            self.setTabColor(COLOR_BURP_ORANGE)
            self.setTabTitle("GAP")
            self.checkIfCancel()
            self.btnCancel.setEnabled(False)
            self.btnCancel.setText("   COMPLETED    ")
            self.progBar.setString("100%")
            self.progBar.setValue(1)
            self.progBar.setMaximum(1)
            self.progStage.text = ""
            if self.getTabIndex() == self.parentTabbedPane.getSelectedIndex():
                time.sleep(0.08)
                self.setTabDefaultColor()
            self.txtDebug.text = ""
            self.txtDebugDetail.text = ""

        except CancelGAPRequested as e:
            # The user pressed the CANCEL GAP button
            self.flagCANCEL = False
            if _debug:
                print("doEverything GAP cancelled")
            self.setTabTitle("GAP")
            self.btnCancel.setEnabled(False)
            self.btnCancel.setText("   CANCELLED    ")
            if (
                self.lblParamList.text.find("UPDATING") >= 0
                or self.lblParamList.text.find("SEARCHING") >= 0
                or self.lblParamList.text.find("PROCESSING") >= 0
            ):
                self.lblParamList.text = "Potential params found - CANCELLED"
            if (
                self.lblLinkList.text.find("UPDATING") >= 0
                or self.lblLinkList.text.find("SEARCHING") >= 0
                or self.lblLinkList.text.find("PROCESSING") >= 0
            ):
                self.lblLinkList.text = "Potential links found - CANCELLED"
            if (
                self.lblWordList.text.find("UPDATING") >= 0
                or self.lblWordList.text.find("SEARCHING") >= 0
                or self.lblWordList.text.find("PROCESSING") >= 0
            ):
                self.lblWordList.text = "Words found - CANCELLED"
            if self.outParamList.text in ("SEARCHING...","UPDATING...","PROCESSING..."):
                self.outParamList.text = "CANCELLED"
            if self.outLinkList.text in ("SEARCHING...","UPDATING...","PROCESSING..."):
                self.outLinkList.text = "CANCELLED"
            if self.outWordList.text in ("SEARCHING...","UPDATING...","PROCESSING..."):
                self.outWordList.text = "CANCELLED"

        except Exception as e:
            self._stderr.println("doEverything 1")
            self._stderr.println(e)

        # Re-enable all fields now the run has finished
        self.setEnabledAll(True)

    def btnCancel_clicked(self, e=None):
        """
        The event for the CANCEL GAP button
        """
        self.flagCANCEL = True
        self.btnCancel.setText(" CANCELLING...  ")
        
    def getBurpParams(self):
        """
        Get all the parameters that Burp identifies as parmeters and add them to the paramUrl_list set.
        """
        try:
            self.txtDebugDetail.text = "getBurpParams"
            if _debug:
                print("getBurpParams started")
            
            for param in self.currentReqResp.getRequestParams():
                # If the parameter is of the type we want to log then get them
                if (
                    (param.getType() == PARAM_URL and self.cbParamUrl.isSelected())
                    or (param.getType() == PARAM_BODY and self.cbParamBody.isSelected())
                    or (
                        param.getType() == PARAM_MULTIPART_ATTR
                        and self.cbParamMultiPart.isSelected()
                    )
                    or (param.getType() == PARAM_JSON and self.cbParamJson.isSelected())
                    or (
                        param.getType() == PARAM_COOKIE
                        and self.cbParamCookie.isSelected()
                    )
                    or (param.getType() == PARAM_XML and self.cbParamXml.isSelected())
                    or (
                        param.getType() == PARAM_XML_ATTR
                        and self.cbParamXmlAttr.isSelected()
                    )
                ):
                    self.addParameter(param.getName().strip(), "Certain", "BURP")
        except Exception as e:
            self._stderr.println("getBurpParams 1")
            self._stderr.println(e)

    def getDefaultSaveDirectory(self):
        """
        If the directory for saved output data isn't valid this will set the default
        """
        # If on Windows then change the file path to the users Documents directory
        # otherwise it will just be in the users home directory
        try:
            osType = System.getProperty("os.name").lower()
            if osType.find("windows") >= 0:
                directory = os.path.expanduser("~") + "\\Documents\\"
            else:
                directory = os.path.expanduser("~")
        except:
            # If an error occurs, just default to '~/'
            directory = "~/"

        return directory
    
    def getMainFilePath(self):
        """
        Get the file path for the cumulative files written if more than one root passed
        """
        try:
            outputDir = self.inSaveDir.text

            try:
                # Try to get the title of the Burp Project from the Title
                try:
                    burpTitle = self.getUiComponent().getParent().getParent().getParent().getParent().getParent().getTitle()
                except:
                    burpTitle = self.getUiComponent().getParent().getParent().getParent().getParent().getParent().getParent().getTitle()
                # Check if it says "Temporary Project". If it does, use "Temp", else get the project name
                if "Temporary Project" in burpTitle:
                    projectName = "TempProject_"
                else:
                    projectName = burpTitle.split(" - ")[1].strip() + "_"
            except:
                projectName = "UnknownProject_"
                pass
                
            fileName = projectName + datetime.now().strftime("%Y%m%d_%H%M%S")

            # Get the type of OS
            osType = System.getProperty("os.name").lower()
            if osType.find("windows") >= 0:
                filepath = outputDir + "\\" + fileName
            else:
                filepath = outputDir + "/" + fileName
            return filepath
        
        except Exception as e:
            self._stderr.println("getMainFilePath 1")
            self._stderr.println(e)
                
    def getFilePath(self, rootname):
        """
        Determine the full path of the output file
        """
        # Create a directory for the root name if it doesn't already exist
        try:
            
            # Set the directory name, and create the directory if necessary
            newDir = urlparse(rootname).scheme + "-" + urlparse(rootname).hostname
            path = os.path.join(self.inSaveDir.text, newDir)
            outputDir = path
            try:
                os.mkdir(path)
            except OSError as e:
                # If the directory already exists then ignore, but any other error set the output directory
                if e.errno != 17: 
                    outputDir = self.inSaveDir.text
            except Exception as e:
                self._stderr.println("getFilePath 2")
                self._stderr.println(e)
            
            # Set the file name    
            fileName = urlparse(rootname).hostname + "_" + datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Get the type of OS
            osType = System.getProperty("os.name").lower()
            if osType.find("windows") >= 0:
                filepath = outputDir + "\\" + fileName
            else:
                filepath = outputDir + "/" + fileName
            return filepath
        
        except Exception as e:
            self._stderr.println("getFilePath 1")
            self._stderr.println(e)
                
    def isLinkInScope(self, link):
        """
        Determines whether the link passed in In Scope according to the Burp API
        """
        # Check if the link may need to be excluded if it is not in scope
        # See if it has already been found first
        self.txtDebugDetail.text = "isLinkInScope: "+link
        try:
            # If the link contains the origin endpoint, then strip that
            if link.find("[") >= 0:
                link = link[0 : link.find("[")]
                
            # If the link contains anything in brackets, then strip the brackets and there contents out of the URL
            if link.find("(") >= 0:
                link = self.REGEX_LINKBRACKET.sub("", link)
                link = link[0 : link.find("(")]
            if link.find("{") >= 0:
                link = self.REGEX_LINKBRACES.sub("", link)
                link = link[0 : link.find("{")]

            # Get from the dictionary
            try:
                newLink = link
                # If the link starts with // then add a protocol just so we can get the potential
                # host to be able to check if it's in scope using the Burp API later
                if newLink.startswith("//"):
                    newLink = "http:" + newLink
                # If the link contains :// then replace the schema with http because the getHost() method will return blank if it's a different scheme, so this is a workaround
                if newLink.find("://") > 0:
                    newLink = "http://" + newLink.split("://")[1]
                
                # Remove wildcards from Host if they exists
                newLink = newLink.replace("*.", "").replace(":*", "").replace("*", "")
                
                host = URL(newLink).getHost()
                # If we could get a host, get that to the dictionary
                inCheckedLinks = self.dictCheckedLinks.get(host)
            except:
                # If we can't get the host, get the link to the dictionary
                host = ""
                return True

            if not inCheckedLinks is None:
                # If found then return the result and don't process further
                inScope = bool(inCheckedLinks)
                return inScope
        except Exception as e:
            self._stderr.println("isLinkInScope 1")
            self._stderr.println(e)

        # Check if the links host is in the selected scope
        inScope = True
        try:
            # If the link has a host (from URL.getHost) and at least one full stop then process further
            if host != "" and host.find(".") >= 0:

                # Initially assume the URL is NOT in scope
                inScope = False

                # From the extracted text, prepend http:// and then check if that is in scope
                try:
                    url = "http://" + host
                    try:
                        # The Burp API needs a java.net.URL object to check if it is in scope
                        # Convert the URL. If it isn't a valid URL an exception is thrown so we can catch and not pass to Burp API
                        oUrl = URL(url)
                        urlHost = str(oUrl.getHost())
                        if urlHost != "":
                            try:
                                # If a URL contains invalid characters then Burp raises an error for some reason when _callbacks.isInScope is done, and it can't be caught, so check it's valid
                                #if self.REGEX_BURPURL.search(url) is not None:
                                if self.REGEX_VALIDHOST.search(urlHost) is not None:
                                    inScope = self._callbacks.isInScope(oUrl)
                                else: 
                                    inScope = True
                            except Exception as e:
                                # Report as being inScope because we can't be sure if it is or not, but we can include just in case
                                inScope = True
                    except Exception as e:
                        # Report as being inScope because we can't be sure if it is or not, but we can include just in case
                        inScope = True

                except Exception as e:
                    self._stderr.println("isLinkInScope 2")
                    self._stderr.println(e)
                    inScope = True

        except Exception as e:
            self._stderr.println("isLinkInScope 3")
            self._stderr.println(e)

        # Add to the dictionary of hosts already checked so we don't need to process it again
        try:
            if host != "":
                self.dictCheckedLinks.update({host: inScope})
        except Exception as e:
            self._stderr.println("isLinkInScope 4")
            self._stderr.println(e)

        return inScope

    def displayResults(self):
        """
        Displays the parameter, links and words information retrieved
        """
        self.txtDebugDetail.text = "displayResults"
        if _debug:
            print("displayResults started")

        # Before starting the results, update the text boxes depending on the options selected
        if self.cbParamsEnabled.isSelected():
            self.lblParamList.text = "Potential params found - PROCESSING"
            self.outParamList.text = "PROCESSING..."
        if self.cbLinksEnabled.isSelected():
            self.lblLinkList.text = "Potential links found - PROCESSING"
            self.outLinkList.text = "PROCESSING..."
        if WORDLIST_IMPORT_ERROR == "":
            if self.cbWordsEnabled.isSelected():
                self.lblWordList.text = "Words found - PROCESSING"
                self.outWordList.text = "PROCESSING..."
    
        # Start a separate thread for Params, Links and Words
        try:
            if self.cbParamsEnabled.isSelected():
                tParam = threading.Thread(target=self.displayParams)
                tParam.daemon = True
                tParam.start()

            if self.cbLinksEnabled.isSelected():
                tLinks = threading.Thread(target=self.displayLinks)
                tLinks.daemon = True
                tLinks.start()
            
            if self.cbWordsEnabled.isSelected():
                tWords = threading.Thread(target=self.displayWords)
                tWords.daemon = True
                tWords.start()
            
            # Join threads so we don't continue until they all finish
            if self.cbParamsEnabled.isSelected():
                tParam.join()
            if self.cbLinksEnabled.isSelected():
                tLinks.join()
            if self.cbWordsEnabled.isSelected():
                tWords.join()

        except Exception as e:
            self._stderr.println("displayResults 1")
            self._stderr.println(e)

    def displayParams(self):
        """
        This is called as a separate thread from displayResults to display the found parameters
        """
        self.txtDebugDetail.text = "displayParams"
        if _debug:
            print("displayParams started")
        try:
            # List all the params, one per line IF the param are enabled
            if self.cbParamsEnabled.isSelected():

                self.lblParamList.text = "Potential params found - UPDATING"
                self.outParamList.text = "UPDATING..."
                self.countParam = len(self.param_list)
                self.countParamSus = len(self.paramSus_list)
                self.countParamSusUnique = len(self.paramSusUrl_list)
                self.countParamUnique = len(self.paramUrl_list)
                self.txtDebug.text = "Displaying Potential params found..."
                
                # De-dupe the lists
                self.txtParamsOnly = "\n".join(sorted(self.param_list))
                self.txtParamsWithURL = "\n".join(sorted(self.paramUrl_list))
                self.txtParamsSusOnly = "\n".join(sorted(self.paramSus_list))
                self.txtParamsSusWithURL = "\n".join(sorted(self.paramSusUrl_list))
                
                if self.txtParamsOnly == "":
                    self.outParamList.text = "NO PARAMETERS FOUND"
                    self.outParamSus.text = "NO PARAMETERS FOUND"
                    self.outParamQuery.text = "NO PARAMETERS FOUND"
                else:
                    if self.cbShowParamOrigin.isSelected():
                        if self.cbShowSusParams.isSelected():
                            self.outParamList.text = self.txtParamsSusWithURL
                        else:
                            self.outParamList.text = self.txtParamsWithURL
                    else:
                        if self.cbShowSusParams.isSelected():
                            self.outParamList.text = self.txtParamsSusOnly
                        else:
                            self.outParamList.text = self.txtParamsOnly

                # Show the version that is selected
                self.cbShowSusParams.setSelected(False)
                self.cbShowQueryString.setSelected(False)
                self.scroll_outParamList.setViewportView(self.outParamList)

                if self.cbShowParamOrigin.isSelected():
                    if self.cbShowSusParams.isSelected():
                        self.lblParamList.text = (
                            "Potential params found - "
                            + str(self.countParamUnique)
                            + " unique:"
                        )
                    else:
                        self.lblParamList.text = (
                            "Potential params found - "
                            + str(self.countParamSusUnique)
                            + " unique:"
                        )
                else:
                    if self.cbShowSusParams.isSelected():
                        self.lblParamList.text = (
                            "Potential params found - "
                            + str(self.countParamSus)
                            + " filtered:"
                        )
                    else:
                        self.lblParamList.text = (
                            "Potential params found - "
                            + str(self.countParam)
                            + " filtered:"
                        )
            
            self.cbShowParamOrigin.setVisible(True)
            if self.countParamUnique > 0:
                self.cbShowParamOrigin.setEnabled(True)
                self.cbShowSusParams.setEnabled(True)
                self.cbShowQueryString.setEnabled(True)
                self.inQueryStringVal.setEnabled(True)
            
            # Write the parameters to a file if required
            self.checkIfCancel()
            if self.cbSaveFile.isSelected():
                self.progBar.setString("Writing files...")
                self.fileWriteParams()

            # Clean up
            self.paramUrl_list.clear()
            self.paramSusUrl_list.clear()
            
        except CancelGAPRequested as e:
            if _debug:
                print("displayParams CancelGAPRequested raised")
            raise CancelGAPRequested("User pressed CANCEL GAP button.")
        except Exception as e:
            self._stderr.println("displayParams 1")
            self._stderr.println(e)

        # Change progress bar
        self.progBar.setValue(self.progBar.getValue()+1)
        
    def displayLinks(self):
        """
        This is called as a separate thread from displayResults to display the found links
        """
        self.txtDebugDetail.text = "displayLinks"
        if _debug:
            print("displayLinks started")
        try:
            # List all the links, one per line, if Links are enabled
            if self.cbLinksEnabled.isSelected():
                
                self.lblLinkList.text = "Potential links found - UPDATING"
                self.outLinkList.text = "UPDATING..."
                self.countLinkUnique = len(self.linkUrl_list)
                self.txtDebug.text = "Displaying Potential links found..."
                
                # De-dupe the lists
                self.txtLinksOnly = "\n".join(sorted(self.link_list))
                self.txtLinksWithURL = "\n".join(sorted(self.linkUrl_list))
                self.txtLinksOnlyInScopeOnly = "\n".join(sorted(self.linkInScope_list))
                self.txtLinksWithURLInScopeOnly = "\n".join(sorted(self.linkUrlInScope_list))
                
                if _debug:
                    print("displayLinks links with URL done")

                # Show the links (and Origin Endpoints if the checkbox is ticked)
                if self.cbShowLinkOrigin.isSelected():
                    if self.cbInScopeOnly.isSelected():
                        self.outLinkList.text = self.txtLinksWithURLInScopeOnly
                    else:
                        self.outLinkList.text = self.txtLinksWithURL
                else:
                    if self.cbInScopeOnly.isSelected():
                        self.outLinkList.text = self.txtLinksOnlyInScopeOnly
                    else:
                        self.outLinkList.text = self.txtLinksOnly

                if self.cbShowLinkOrigin.isSelected() and not self.cbInScopeOnly.isSelected():
                    self.lblLinkList.text = (
                        "Potential links found - "
                        + str(self.countLinkUnique)
                        + " unique:"
                    )
                else:
                    self.lblLinkList.text = (
                        "Potential links found - "
                        + str(self.outLinkList.getLineCount())
                        + " filtered:"
                    )

                self.cbShowLinkOrigin.setVisible(True)
                self.cbInScopeOnly.setVisible(True)

                # If no links were found, write that in the text box
                if self.outLinkList.text == "":
                    self.outLinkList.text = "NO LINKS FOUND"
                if self.countLinkUnique > 0:
                    self.cbShowLinkOrigin.setEnabled(True)
                    self.cbInScopeOnly.setEnabled(True)
                    self.inLinkFilter.setEnabled(True)
                    self.cbLinkCaseSens.setEnabled(True)
                    self.btnFilter.setEnabled(True)
                    self.cbExclusions.setEnabled(True)
                    self.inExclusions.setEnabled(True)

            # Write the links to a file if required
            self.checkIfCancel()
            if self.cbSaveFile.isSelected():
                self.progBar.setString("Writing files...")
                self.fileWriteLinks()

            # Clean up
            self.link_list.clear()
            self.linkUrl_list.clear()
            self.linkInScope_list.clear()
            self.linkUrlInScope_list.clear()
            
        except CancelGAPRequested as e:
            if _debug:
                print("displayLinks CancelGAPRequested raised")
            raise CancelGAPRequested("User pressed CANCEL GAP button.")
        except Exception as e:
            self._stderr.println("displayLinks 1")
            self._stderr.println(e)
            
        # Change progress bar
        self.progBar.setValue(self.progBar.getValue()+1)
        
    def displayWords(self):
        """
        This is called as a separate thread from displayResults to display the found words
        """
        self.txtDebugDetail.text = "displayWords"
        if _debug:
            print("displayWords started")
        if WORDLIST_IMPORT_ERROR != "":
            self.lblWordList.text = "Words found - UNAVAILABLE:"
            self.outWordList.text = WORDLIST_IMPORT_ERROR
            self.outWordList.text = self.outWordList.text + "\nSee Help for more details."
        else:
            try:
                # List all the words, one per line IF the words are enabled
                if self.cbWordsEnabled.isSelected():
                    
                    self.lblWordList.text = "Words found - UPDATING"
                    self.outWordList.text = "UPDATING..."
                    self.countWordUnique = len(self.wordUrl_list)
                    self.txtDebug.text = "Displaying Words found..."
                    
                    # De-dupe the lists
                    self.txtWordsOnly = "\n".join(sorted(self.word_list))
                    self.txtWordsWithURL = "\n".join(sorted(self.wordUrl_list))
                    
                    if self.txtWordsOnly == "":
                        self.outWordList.text = "NO WORDS FOUND"
                    else:
                        if self.cbShowWordOrigin.isSelected():
                            self.outWordList.text = self.txtWordsWithURL
                        else:
                            self.outWordList.text = self.txtWordsOnly
                    self.scroll_outWordList.setViewportView(self.outWordList)

                    #if str(self.countWordUnique) == str(self.outWordList.getLineCount()-1):
                    if self.cbShowWordOrigin.isSelected():
                        self.lblWordList.text = (
                            "Words found - "
                            + str(self.countWordUnique)
                            + " unique:"
                        )
                    else:
                        self.lblWordList.text = (
                            "Words found - "
                            + str(self.outWordList.getLineCount())
                            + " filtered:"
                        )

                self.cbShowWordOrigin.setVisible(True)
                if self.countWordUnique > 0:
                    self.cbShowWordOrigin.setEnabled(True)
                    
                # Write the words to a file if required
                self.checkIfCancel()
                if self.cbSaveFile.isSelected():
                    self.progBar.setString("Writing files...")
                    self.fileWriteWords()

                # Clean up
                self.word_list.clear()
                self.wordUrl_list.clear()
                
            except CancelGAPRequested as e:
                if _debug:
                    print("displayWords CancelGAPRequested raised")
                raise CancelGAPRequested("User pressed CANCEL GAP button.")
            except Exception as e:
                self._stderr.println("displayWords 1")
                self._stderr.println(e)
            
        # Change progress bar
        self.progBar.setValue(self.progBar.getValue()+1)
            
    def fileWriteParams(self):
        """
        Writes the parameters to a file in the requested directory
        """
        self.txtDebugDetail.text = "fileWriteParams"
        if _debug:
            print("fileWriteParams started")
        try:
            # Write all parameters to a file if any exist and its enabled
            self.checkIfCancel()
            if self.cbParamsEnabled.isSelected():
                if self.outParamList.text != "NO PARAMETERS FOUND":
                    
                    showParamOrigin = self.cbShowParamOrigin.isSelected()
                    
                    # Write all parameters as one file to the root directory, with the project name, unless there is only one root selected
                    if len(self.roots) > 1:
                        fileName = os.path.expanduser(self.getMainFilePath() + "_params.txt")
                        self.txtDebug.text = "Writing file " + fileName
                        with open(fileName, "w") as f:
                            self.checkIfCancel()
                            try:
                                if showParamOrigin:
                                    f.write(self.txtParamsWithURL.encode("UTF-8").replace("  "," "))
                                else:
                                    f.write(self.txtParamsOnly.encode("UTF-8"))
                                f.write("\n".encode("UTF-8"))
                                f.close()
                            except Exception as e:
                                self._stderr.println("fileWriteParams 2")
                                self._stderr.println(e)
                                
                    # Write a file for each root, to the roots directory
                    if len(self.roots) == 1:
                        for root in self.roots:
                            fileName = os.path.expanduser(self.getFilePath(root) + "_params.txt")
                            self.txtDebug.text = "Writing file " + fileName
                            with open(fileName, "w") as f:
                                self.checkIfCancel()
                                try:
                                    if showParamOrigin:
                                        f.write(self.txtParamsWithURL.encode("UTF-8").replace("  "," "))
                                    else:
                                       f.write(self.txtParamsOnly.encode("UTF-8"))
                                    f.write("\n".encode("UTF-8"))
                                    f.close()
                                except Exception as e:
                                    self._stderr.println("fileWriteParams 3")
                                    self._stderr.println(e)
                    else:
                        for root in self.roots:
                            fileText = ""
                            # Just get list of params for the root
                            self.checkIfCancel()
                            try:
                                for param in self.txtParamsWithURL.encode("UTF-8").splitlines():
                                    self.checkIfCancel()
                                    if "["+root in param or "[GAP]" in param:
                                        if showParamOrigin:
                                            fileText = fileText + param.replace("  "," ")+"\n"
                                        else:
                                            fileText = fileText + param.split("  [")[0]+"\n"
                                    
                            except Exception as e:
                                self._stderr.println("fileWriteParams 4")
                                self._stderr.println(e)
                                    
                            # Write params to file if there were any
                            if fileText != "":
                                fileText = "\n".join(sorted(set(fileText.split())))
                                fileName = os.path.expanduser(self.getFilePath(root) + "_params.txt")
                                self.txtDebug.text = "Writing file " + fileName
                                with open(fileName, "w") as f:
                                    try:
                                        f.write(fileText)
                                        f.write("\n".encode("UTF-8"))
                                        f.close
                                    except Exception as e:
                                        self._stderr.println("fileWriteParams 5")
                                        self._stderr.println(e)
                                
        except IOError as e:
            self._stderr.println("There is a problem with the Save directory " + self.inSaveDir.text + ". Check it and correct it.")
        except CancelGAPRequested as e:
            if _debug:
                print("fileWriteParams CancelGAPRequested raised")
            raise CancelGAPRequested("User pressed CANCEL GAP button.")
        except Exception as e:
            self._stderr.println("fileWriteParams 1")
            self._stderr.println(e)

    def fileWriteLinks(self):
        """
        Writes the links to a file in the requested directory
        """
        self.txtDebugDetail.text = "fileWriteLinks"
        if _debug:
            print("fileWriteLinks started")
        try:
            # Write all links to a file if any exist
            self.checkIfCancel()
            if self.cbLinksEnabled.isSelected():
                if self.outLinkList.text != "NO LINKS FOUND":

                    showLinkOrigin = self.cbShowLinkOrigin.isSelected()
                    inScopeOnly = self.cbInScopeOnly.isSelected()
                    
                    # Write all links as one file to the root directory, with the project name, unless there is only one root selected
                    if len(self.roots) > 1:
                        fileName = os.path.expanduser(self.getMainFilePath() + "_links.txt")
                        self.txtDebug.text = "Writing file " + fileName
                        with open(fileName, "w") as f:
                            self.checkIfCancel()
                            try:
                                if showLinkOrigin:
                                    if inScopeOnly:
                                        f.write(self.txtLinksWithURLInScopeOnly.encode("UTF-8").replace("  "," "))
                                    else:
                                        f.write(self.txtLinksWithURL.encode("UTF-8").replace("  "," "))
                                else:
                                    if inScopeOnly:
                                        f.write(self.txtLinksOnlyInScopeOnly.encode("UTF-8"))
                                    else:
                                        f.write(self.txtLinksOnly.encode("UTF-8"))
                                f.write("\n".encode("UTF-8"))
                                f.close()
                            except Exception as e:
                                self._stderr.println("fileWriteLinks 2")
                                self._stderr.println(e)
                                
                    # Write a file for each root, to the roots directory
                    if len(self.roots) == 1:
                        for root in self.roots:
                            fileName = os.path.expanduser(self.getFilePath(root) + "_links.txt")
                            self.txtDebug.text = "Writing file " + fileName
                            with open(fileName, "w") as f:
                                self.checkIfCancel()
                                try:
                                    if showLinkOrigin:
                                        if inScopeOnly:
                                            f.write(self.txtLinksWithURLInScopeOnly.encode("UTF-8").replace("  "," "))
                                        else:
                                            f.write(self.txtLinksWithURL.encode("UTF-8").replace("  "," "))
                                    else:
                                        if inScopeOnly:
                                            f.write(self.txtLinksOnlyInScopeOnly.encode("UTF-8"))
                                        else:
                                            f.write(self.txtLinksOnly.encode("UTF-8"))
                                    f.write("\n".encode("UTF-8"))
                                    f.close()
                                except Exception as e:
                                    self._stderr.println("fileWriteLinks 3")
                                    self._stderr.println(e)
                    else:
                        for root in self.roots:
                            fileText = ""
                            # Just get list of links for the root
                            self.checkIfCancel()
                            try:
                                if inScopeOnly:
                                    for line in self.txtLinksWithURLInScopeOnly.encode("UTF-8").splitlines():
                                        self.checkIfCancel()
                                        if "["+root in line or "[GAP]" in line:
                                            if self.cbShowLinkOrigin.isSelected():
                                                fileText = fileText + line.replace("  "," ")+"\n"
                                            else:
                                                fileText = fileText + line.split("  [")[0]+"\n"
                                else:
                                    for line in self.txtLinksWithURL.encode("UTF-8").splitlines():
                                        self.checkIfCancel()
                                        if "["+root in line or "[GAP]" in line:
                                            if showLinkOrigin:
                                                fileText = fileText + line.replace("  "," ")+"\n"
                                            else:
                                                fileText = fileText + line.split("  [")[0]+"\n"
                                    
                            except Exception as e:
                                self._stderr.println("fileWriteLinks 4")
                                self._stderr.println(e)
                                    
                            # Write links to file if there were any
                            if fileText != "":
                                fileText = "\n".join(sorted(set(fileText.split())))
                                fileName = os.path.expanduser(self.getFilePath(root) + "_links.txt")
                                self.txtDebug.text = "Writing file " + fileName
                                with open(fileName, "w") as f:
                                    try:
                                        f.write(fileText)
                                        f.write("\n".encode("UTF-8"))
                                        f.close
                                    except Exception as e:
                                        self._stderr.println("fileWriteLinks 5")
                                        self._stderr.println(e)
                                    
        except IOError as e:
                self._stderr.println("There is a problem with the Save directory " + self.inSaveDir.text + ". Check it and correct it.")
                self._stderr.println(e)
        except CancelGAPRequested as e:
            if _debug:
                print("fileWriteLinks CancelGAPRequested raised")
            raise CancelGAPRequested("User pressed CANCEL GAP button.")
        except Exception as e:
            self._stderr.println("fileWriteLinks 1")
            self._stderr.println(e)

    def fileWriteWords(self):
        """
        Writes the words to a file in the requested directory
        """
        self.txtDebugDetail.text = "fileWriteWords"
        if _debug:
            print("fileWriteWords started")
        if WORDLIST_IMPORT_ERROR != "":
            self.lblWordList.text = "Words found - UNAVAILABLE:"
            self.outWordList.text = WORDLIST_IMPORT_ERROR
        else:
            try:
                # Write all words to a file if any exist and its enabled
                self.checkIfCancel()
                if self.cbWordsEnabled.isSelected():
                    if self.outWordList.text != "NO WORDS FOUND":

                        showWordOrigin = self.cbShowWordOrigin.isSelected()
                        
                        # Write all words as one file to the root directory, with the project name, unless there is only one root selected
                        if len(self.roots) > 1:
                            fileName = os.path.expanduser(self.getMainFilePath() + "_words.txt")
                            self.txtDebug.text = "Writing file " + fileName
                            with open(fileName, "w") as f:
                                self.checkIfCancel()
                                try:
                                    if showWordOrigin:
                                        f.write(self.txtWordsWithURL.encode("UTF-8").replace("  "," "))
                                    else:
                                        f.write(self.txtWordsOnly.encode("UTF-8"))
                                    f.write("\n".encode("UTF-8"))
                                    f.close()
                                except Exception as e:
                                    self._stderr.println("fileWriteWords 2")
                                    self._stderr.println(e)
                                    
                        # Write a file for each root, to the roots directory
                        if len(self.roots) == 1:
                            for root in self.roots:
                                fileName = os.path.expanduser(self.getFilePath(root) + "_words.txt")
                                self.txtDebug.text = "Writing file " + fileName
                                with open(fileName, "w") as f:
                                    self.checkIfCancel()
                                    try:
                                        if showWordOrigin:
                                            f.write(self.txtWordsWithURL.encode("UTF-8").replace("  "," "))
                                        else:
                                            f.write(self.txtWordsOnly.encode("UTF-8"))
                                        f.write("\n".encode("UTF-8"))
                                        f.close()
                                    except Exception as e:
                                        self._stderr.println("fileWriteWords 3")
                                        self._stderr.println(e)
                        else:
                            for root in self.roots:
                                fileText = ""
                                # Just get list of words for the root
                                self.checkIfCancel()
                                try:
                                    for word in self.txtWordsWithURL.encode("UTF-8").splitlines():
                                        self.checkIfCancel()
                                        if "["+root in word or "[GAP]" in word:
                                            if showWordOrigin:
                                                fileText = fileText + word.replace("  "," ")+"\n"
                                            else:
                                                fileText = fileText + word.split("  [")[0]+"\n"
                                        
                                except Exception as e:
                                    self._stderr.println("fileWriteWords 4")
                                    self._stderr.println(e)
                                        
                                # Write words to file if there were any
                                if fileText != "":
                                    fileText = "\n".join(sorted(set(fileText.split())))
                                    fileName = os.path.expanduser(self.getFilePath(root) + "_words.txt")
                                    self.txtDebug.text = "Writing file " + fileName
                                    with open(fileName, "w") as f:
                                        try:
                                            f.write(fileText)
                                            f.write("\n".encode("UTF-8"))
                                            f.close
                                        except Exception as e:
                                            self._stderr.println("fileWriteWords 5")
                                            self._stderr.println(e)
            except IOError as e:
                self._stderr.println("There is a problem with the Save directory " + self.inSaveDir.text + ". Check it and correct it.")
            except CancelGAPRequested as e:
                if _debug:
                    print("fileWriteWords CancelGAPRequested raised")
                raise CancelGAPRequested("User pressed CANCEL GAP button.")
            except Exception as e:
                self._stderr.println("fileWriteWords 1")
                self._stderr.println(e)
    
    def getRequestParams(self):
        """
        Get potential parmeters from JSON that may be in the request
        """
        self.txtDebugDetail.text = "getRequestParams"
        if _debug:
            print("getRequestParams started")
        try:
            paramsProcessed = set()
            
            # Get any potential JSON strings that are between { and }
            possibleJSON = self.REGEX_PARAMSJSON.finditer(self.currentReqResp.getRequestBody())
            for key in possibleJSON:
                self.checkIfCancel()
                if key is not None and key.group() != "":
                    possibleParams = self.REGEX_PARAMSJSONPARAMS.finditer(key.group())
                    for param in possibleParams:     
                        self.checkIfCancel()
                        # If the param has already been processed, skip to the next
                        if param in paramsProcessed:
                            continue
                        else:
                            paramsProcessed.add(param)
                            
                        if param is not None and param.group() != "":      
                            if _debug:
                                print("  getRequestParams param: "+param.group())
                            self.addParameter(param.group(), "Firm", "REQUEST")
            
        except Exception as e:
            if not self.flagCANCEL:
                self._stderr.println("getRequestParams 1")
                self._stderr.println(e)
                
    def getResponseParams(self):
        """
        Get XML and JSON responses, extract keys and add them to the paramUrl_list
        Original contributor: @_pichik
        In addition it will extract name and id from <input> fields in HTML
        """
        self.txtDebugDetail.text = "getResponseParams"
        if _debug:
            print("getResponseParams started")
        try:

            # If it is content-type we want to process then carry on
            if self.currentContentTypeInclude:

                body = self.currentReqResp.getResponseBody()
                mimeType = self.currentReqResp.getResponseMIMEType()
                paramsProcessed = set()
                
                # Get parameters from the response where they are like &PARAM= or ?PARAM=
                try:
                    possibleParams = self.REGEX_PARAMSPOSSIBLE.finditer(body)
                    for key in possibleParams:
                        
                        self.checkIfCancel()
                        if key is not None and key.group() != "":
                            param = key.group().replace("%5c","")
                            
                            # If the param has already been processed, skip to the next
                            if param in paramsProcessed:
                                continue
                            else:
                                paramsProcessed.add(param)

                            if _debug:
                                print("  getResponseParams param: "+param)
                            
                            param = self.REGEX_PARAMSSUB.sub("",param).strip()
                            param = param.replace("\\","").replace("&","")
                            self.addParameter(param, "Tentative", "RESPONSE")
                except Exception as e:
                    self._stderr.println("getResponseParams 9")
                    self._stderr.println(e)
                
                # If any of the options were picked, then carry on
                if (self.cbParamJSONResponse.isSelected() or self.cbParamXMLResponse.isSelected() or self.cbParamInputField.isSelected() or self.cbParamJSVars.isSelected()):     
                                    
                    # Get regardless of the content type
                    # Javascript variable could be in the html, script and even JSON response within a .js.map file
                    if self.cbParamJSVars.isSelected():

                        # Get inline javascript variables defined with "let"
                        try:
                            js_keys = self.REGEX_JSLET.finditer(body)
                            for key in js_keys:
                                self.checkIfCancel()
                                if key is not None and key.group() != "":
                                    self.addParameter(key.group().strip(), "Tentative", "RESPONSE")
                        except Exception as e:
                            self._stderr.println("getResponseParams 1")
                            self._stderr.println(e)

                        # Get inline javascript variables defined with "var"
                        try:
                            js_keys = self.REGEX_JSVAR.finditer(body)
                            for key in js_keys:
                                self.checkIfCancel()
                                if key is not None and key.group() != "":
                                    self.addParameter(key.group().strip(),  "Tentative", "RESPONSE")
                        except Exception as e:
                            self._stderr.println("getResponseParams 2")
                            self._stderr.println(e)

                        # Get inline javascript constants
                        try:
                            js_keys = self.REGEX_JSCONSTS.finditer(body)
                            for key in js_keys:
                                self.checkIfCancel()
                                if key is not None and key.group() != "":
                                    self.addParameter(key.group().strip(), "Tentative", "RESPONSE")
                        except Exception as e:
                            self._stderr.println("getResponseParams 3")
                            self._stderr.println(e)

                    # If mime type is JSON then get the JSON attributes
                    if mimeType == "JSON":
                        if self.cbParamJSONResponse.isSelected():
                            try:
                                # Get only keys from json (everything between double quotes:)
                                json_keys = self.REGEX_JSONKEYS.findall(body)
                                for key in json_keys:
                                    self.checkIfCancel()
                                    self.addParameter(key.strip(), "Tentative", "RESPONSE")
                            except Exception as e:
                                self._stderr.println("getResponseParams 4")
                                self._stderr.println(e)

                    # If the mime type is XML then get the xml keys
                    elif mimeType == "XML":
                        if self.cbParamXMLResponse.isSelected():
                            try:
                                # Get XML attributes
                                xml_keys = self.REGEX_XMLATTR.findall(body)
                                for key in xml_keys:
                                    self.checkIfCancel()
                                    self.addParameter(key.strip(), "Tentative", "RESPONSE")
                            except Exception as e:
                                self._stderr.println("getResponseParams 5")
                                self._stderr.println(e)

                    # If the mime type is HTML then get <input> name and id values, and meta tag names
                    elif mimeType == "HTML":

                        if self.cbParamInputField.isSelected():
                            # Get Input field name and id attributes
                            try:
                                html_keys = self.REGEX_HTMLINP.findall(body)
                                for key in html_keys:
                                    self.checkIfCancel()
                                    input_name = self.REGEX_HTMLINP_NAME.search(key)
                                    if input_name is not None and input_name.group() != "":
                                        input_name_val = input_name.group()
                                        input_name_val = input_name_val.replace("=", "")
                                        input_name_val = input_name_val.replace('"', "")
                                        input_name_val = input_name_val.replace("'", "")
                                        self.addParameter(input_name_val.strip(), "Tentative", "RESPONSE")
                                    input_id = self.REGEX_HTMLINP_ID.search(key)
                                    if input_id is not None and input_id.group() != "":
                                        input_id_val = input_id.group()
                                        input_id_val = input_id_val.replace("=", "")
                                        input_id_val = input_id_val.replace('"', "")
                                        input_id_val = input_id_val.replace("'", "")
                                        self.addParameter(input_id_val.strip(), "Tentative", "RESPONSE")
                            except Exception as e:
                                self._stderr.println("getResponseParams 6")
                                self._stderr.println(e)

        except Exception as e:
            if not self.flagCANCEL:
                self._stderr.println("getResponseParams 8")
                self._stderr.println(e)

    def includeLink(self, link):
        """
        Determine if the passed Link should be excluded by checking the list of exclusions (if selected)
        Returns whether the link should be included
        """
        self.txtDebugDetail.text = "includeLink: "+link
        include = True

        # Exclude if the finding is an endpoint link but has more than one newline character. This is a false
        # positive that can sometimes be raised by the regex
        # And exclude if the link:
        # - starts with literal characters \n
        # - starts with #
        # - starts with \
        # - has any white space characters in
        # - has any new line characters in
        # - doesn't have any letters or numbers in
        # - doesn't have \s or \S in, because it's probably a regex, not a link
        # - has character non printable ascii characters in it
        # - starts with /=
        # - starts with application/, image/, model/, video/, audio/ or text/ as this is a content-type that can sometimes be confused for links
        try:
            if link.count("\n") > 1 or link.startswith("#") or link.startswith("$") or link.startswith("\\") or link.startswith("/="):
                include = False
            if include:
                include = not (bool(re.search(r"\s", link)))
            if include:
                include = not (bool(re.search(r"\n", link)))
            if include:
                include = bool(re.search(r"[0-9a-zA-Z]", link))
            if include:
                include = not (bool(re.search(r"\\(s|S)", link)))
            if include:
                include = not (bool(re.match(r"^(application\/|image\/|model\/|video\/|audio\/|text\/)", link, re.IGNORECASE)))
            for char in link:
                if ord(char) < 32:
                    include = False
                    break
        except Exception as e:
            self._stderr.println("includeLink 2")
            self._stderr.println(e)

        # Only check the exclusion list the "Link exclusions" check box is selected
        if include and self.cbExclusions.isSelected():
            # Get the exclusions
            try:
                lstExclusions = self.inExclusions.text.split(",")
            except:
                self._stderr.println("Exclusion list invalid. Using default list")
                lstExclusions = DEFAULT_EXCLUSIONS.split(",")

            # Go through lstExclusions and see if finding contains any. If not then continue
            # If it fails then try URL encoding and then checking
            linkWithoutQueryString = link.split("?")[0].lower()
            for exc in lstExclusions:
                try:
                    if linkWithoutQueryString.encode(encoding="ascii",errors="ignore").find(exc.lower()) >= 0:
                        include = False
                except Exception as e:
                    include = False
                    self._stderr.println(
                        "includeLink 1: Failed to check exclusions for a finding on URL: "
                        + link
                    )
                    self._stderr.println(e)

        return include

    def includeFile(self, url):
        """
        Determine if the passed should be excluded by checking the list of exclusions
        Returns whether the url should be included
        """
        self.txtDebugDetail.text = "includeFile: "+url
        try:
            include = True
            
            # Set the file extension exclusions
            lstFileExtExclusions = FILEEXT_EXCLUSIONS.split(",")
            
            # Go through FILEEXT_EXCLUSIONS and see if finding contains any. If not then continue
            for exc in lstFileExtExclusions:
                try:
                    if url.endswith(exc.lower()):
                        include = False
                except Exception as e:
                    self._stderr.println("ERROR includeFile 2")
                    self._stderr.println(e)

        except Exception as e:
            self._stderr.println("ERROR includeFile 1")
            self._stderr.println(e)

        return include

    def includeContentType(self):
        """
        Determine if the content type is in the exclusions
        Returns whether the content type is included
        """
        self.txtDebugDetail.text = "includeContentType"
        if _debug:
            print("includeContentType started")
        include = True

        try:
            contentType = self.currentReqResp.getResponseContentType()
            url = self.currentReqResp.getRequestUrl()
            
            # Check against file extensions
            url = url.split("?")[0].split("#")[0].split("/")[-1]
            if url.find(".") > 0:
                include = self.includeFile(url)
            
            # Check against the content-type
            if include and contentType != "": 
                # Check the content-type against the comma separated list of exclusions
                lstExcludeContentType = CONTENTTYPE_EXCLUSIONS.split(",")
                for excludeContentType in lstExcludeContentType:
                    self.checkIfCancel()
                    if contentType.lower() == excludeContentType.lower():
                        include = False
                        break
                                
            if (_debug or self.logContentType) and include:
                print("Content-Type included: "+contentType)
        
        except Exception as e:
            self._stderr.println("ERROR includeContentType 1")
            self._stderr.println(e)
            
        return include

    def getResponseLinks(self):
        """
        Get a list of links found
        """
        self.txtDebugDetail.text = "getResponseLinks"
        if _debug:
            print("getResponseLinks started")

        linksProcessed = set()
        header = self.currentReqResp.getResponseHeaders()
        responseUrl = self.currentReqResp.getRequestUrl()
        
        # If it is content-type we want to process then carry on
        if self.currentContentTypeInclude:
            
            # Some URLs may be displayed in the body within strings that have different encodings of / and : so replace these
            body = self.currentReqResp.getResponseBody()
            body = self.REGEX_LINKSSLASH.sub("/", body)
            body = self.REGEX_LINKSCOLON.sub(":", body)
            
            # Replace occurrences of HTML entity &quot; with an actual double quote
            body = body.replace('&quot;','"')
            # Replace occurrences of HTML entity &nbsp; with an actual space
            body = body.replace('&nbsp;',' ')
            
            try:
                search = header.replace(" ","\n").encode("utf-8")+body.encode("utf-8")
                try:
                    link_keys = self.REGEX_LINKS.finditer(search)
                except Exception as e:
                    self._stderr.println("getResponseParams 4")
                    self._stderr.println(e)

                for key in link_keys:
                    self.checkIfCancel()
                    if key is not None and len(key.group().strip()) > 1:
                        link = key.group().strip()

                        # If the link has been processed already, skip to the next
                        if link in linksProcessed:
                            continue
                        else:
                            linksProcessed.add(link)
                        
                        if _debug:
                            print("  getResponseLinks link: "+link)
                        
                        link = link.strip("\"'\n\r( ")
                        link = link.replace("\\n", "")
                        link = link.replace("\\r", "")
                        link = link.replace("\\.", ".")

                        try:
                            first = link[:1]
                            last = link[-1]
                            firstTwo = link[:2]
                            lastTwo = link[-2]

                            if (
                                first == '"'
                                or first == "'"
                                or first == "\n"
                                or first == "\r"
                                or firstTwo == "\\n"
                                or firstTwo == "\\r"
                            ) and (
                                last == '"'
                                or last == "'"
                                or last == "\n"
                                or last == "\r"
                                or lastTwo == "\\n"
                                or lastTwo == "\\r"
                            ):
                                if firstTwo == "\\n" or firstTwo == "\\r":
                                    start = 2
                                else:
                                    start = 1
                                if lastTwo == "\\n" or lastTwo == "\\r":
                                    end = 2
                                else:
                                    end = 1
                                link = link[start:-end]

                            # If there are any trailing back slashes, comma, =, :, ; or >; remove them all
                            link = link.rstrip("\\")
                            link = link.rstrip(">;")
                            link = link.rstrip(";")
                            link = link.rstrip(",")
                            link = link.rstrip("=")
                            link = link.rstrip(":")
                            
                            # If there are any backticks in the URL, remove everything from the backtick onwards
                            link = link.split("`")[0]
                            
                            # If there are any closing brackets of any kind without an opening bracket, remove everything from the closing bracket onwards
                            if self.REGEX_LINKSEARCH1.search(link):
                                link = link.split(")", 1)[0]
                            if self.REGEX_LINKSEARCH2.search(link):
                                link = link.split("}", 1)[0]
                            if self.REGEX_LINKSEARCH3.search(link):
                                link = link.split("]", 1)[0]    
                                
                            # If there is a </ in the link then strip from that forward
                            if self.REGEX_LINKSEARCH4.search(link):
                                link = link.split("</", 1)[0]                           
                        
                        except Exception as e:
                            self._stderr.println("getResponseLinks 2")
                            self._stderr.println(e)
                            try:
                                self._stderr.println("The link that caused the error: " + link)
                            except:
                                pass

                        # If the link starts with a . and the  2nd character is not a . or / then remove the first .
                        if link[0] == "." and link[1] != "." and link[1] != "/":
                            link = link[1:]

                        # Determine if Link should be included
                        include = self.includeLink(link)

                        # If the link found is for a .js.map file then put the full .map URL in the list
                        if link.find("//# sourceMappingURL") >= 0:
                            include = True

                            # Get .map link after the =
                            firstpos = link.rfind("=")
                            lastpos = link.find("\n")
                            if lastpos <= 0:
                                lastpos = len(link)
                            mapFile = link[firstpos + 1 : lastpos]

                            # Get the response url up to last /
                            lastpos = responseUrl.rfind("/")
                            mapPath = responseUrl[0 : lastpos + 1]

                            # Add them to get link of js.map and add to list
                            link = mapPath + mapFile
                            link = link.replace("\n", "")

                        # If a link starts with // then add http:
                        if link.startswith("//"):
                            link = "http:" + link

                        # Only add the finding if it should be included
                        if include:
                            self.addLink(link,responseUrl)

                            # Get parameters from links if requested, Parameters mode is enabled AND the link is in scope
                            if (
                                self.cbParamFromLinks.isSelected()
                                and self.cbParamsEnabled.isSelected()
                                and link.find("?") > 0
                                and self.isLinkInScope(link)
                            ):
                                # Get parameters from the link
                                try:
                                    link = link.replace("%5c","").replace("\\","")
                                    link = self.REGEX_LINKSAND.sub("&", link)
                                    link = self.REGEX_LINKSEQUAL.sub("=", link)
                                    param_keys = self.REGEX_PARAMKEYS.finditer(link)
                                    for param in param_keys:
                                        if _debug:
                                            print("    getResponseLinks param: "+str(param.group()))
                                        self.checkIfCancel()
                                        if param is not None and param.group() != "":
                                            self.addParameter(param.group().strip(), "Firm", "RESPLINKS")
                                except Exception as e:
                                    self._stderr.println("getResponseLinks 3")
                                    self._stderr.println(e)
            except Exception as e:
                if not self.flagCANCEL:
                    self._stderr.println("getResponseLinks 1")
                    self._stderr.println(e)
                    try:
                        self._stderr.println("The link that caused the error: " + link)
                    except:
                        pass
            
        # Also add a link of a js.map file if the X-SourceMap or SourceMap header exists
        try:
            # See if the SourceMap header exists
            try:
                mapFile = self.REGEX_SOURCEMAP.findall(header)[0]
            except:
                mapFile = ""
            # If a map file was found in the response, then add a link for it
            if mapFile != "":
                self.addLink(mapFile,responseUrl)
        except Exception as e:
            self._stderr.println("getResponseLinks 4")
            self._stderr.println(e)

    def getResponseWords(self):
        """
        Get a list of words found
        """
        self.txtDebugDetail.text = "getResponseWords"
        if _debug:
            print("getResponseWords started")
        try:
            # If it is content-type we want to process then carry on
            if self.currentContentTypeInclude:
                
                contentType = self.currentReqResp.getResponseContentType()
                mimeType = self.currentReqResp.getResponseMIMEType()
                responseUrl = self.currentReqResp.getRequestUrl()
                wordsProcessed = set()
                
                # If it's a content type we want to retrieve words from then search
                if (mimeType in ("HTML","XML","JSON","PLAIN") or contentType.lower() in DEFAULT_WORDS_CONTENT_TYPES) and responseUrl.lower().find(".js.map") < 0:
                    
                    body = self.currentReqResp.getResponseBody()
                    
                    # Parse html content with beautifulsoup4
                    # If html5lib is installed then use that as a parser. It is slower than the default, but is more accurate and doesn't throw runtime errors
                    allText = ""
                    try:
                        if html5libInstalled:
                            soup = BeautifulSoup(body, "html5lib")
                        else:
                            soup = BeautifulSoup(body, "html.parser")
                    except Exception as e:
                        self._stderr.println("getResponseWords 2")
                        self._stderr.println(e)
                    
                    # Get words from meta tag contents
                    for tag in soup.find_all("meta", content=True):
                        self.checkIfCancel()
                        if tag.get("property", "") in ["og:title","og:description","title","og:site_name","fb:admins"] or tag.get("name", "") in ["description","keywords","twitter:title","twitter:description","application-name","author","subject","copyright","abstract","topic","summary","owner","directory","category","og:title","og:type","og:site_name","og:description","csrf-param","apple-mobile-web-app-title","twitter:label1","twitter:data1","twitter:label2","twitter:data2","twitter:title"]:
                            allText = allText + tag['content'] + ' '

                    # Get words from link tag titles
                    for tag in soup.find_all("link", content=True):
                        self.checkIfCancel()
                        if tag.get("rel", "") in ["alternate","index","start","prev","next","search"]:
                            allText = allText + tag['title'] + ' '
        
                    # Get words from any "alt" attribute of images if required
                    if self.cbWordImgAlt.isSelected():
                        for img in soup.find_all('img', alt=True):
                            self.checkIfCancel()
                            allText = allText + img['alt'] + ' '

                    # Get words from any comments if required
                    if self.cbWordComments.isSelected():
                        for comment in soup.find_all(string=lambda text:isinstance(text, Comment)):
                            self.checkIfCancel()
                            allText = allText + comment + ' '
    
                    # Remove tags we don't want content from
                    for data in soup(['style', 'script', 'link']): 
                        self.checkIfCancel()
                        data.decompose()

                    # Get words from the body text
                    allText = allText + " ".join(soup.stripped_strings)
                    
                    # Build list of potential words over 3 characters long, that don't appear in url paths
                    potentialWords = self.REGEX_WORDS.findall(allText)
                    potentialWords = set(potentialWords) 
                    
                    # Process all words found
                    for word in potentialWords:
                        
                        # If the word has already been processes, skip to the next
                        if word in wordsProcessed:
                            continue
                        else:
                            wordsProcessed.add(word)
                        
                        if _debug:
                            print("  getResponseWords word: "+word)
                                    
                        # Ignore certain words if found in robots.txt
                        if responseUrl.lower().find("robots.txt") > 0 and word in ("allow","disallow","sitemap","user-agent"):
                            continue
                        word = self.sanitizeWord(word)
                        self.checkIfCancel()

                        # If "Include word with digits" is checked, only proceed with word if it has no digits
                        if not (self.cbWordDigits and any(char.isdigit() for char in word)):

                            if word.upper().isupper():
                                # strip apostrophes
                                word = word.replace("'", "")
                                # add the word to the list if not a stop word and is not above the max length
                                if len(word) > 0 and word.lower() not in self.lstStopWords and (self.inWordsMaxlen.text == "0" or len(word) <= int(self.inWordsMaxlen.text)):
                                    self.word_list.add(word)
                                    self.wordUrl_list.add(word + "  [" + responseUrl + "]")
                                    if self.cbWordLower.isSelected() and word != word.lower():
                                        self.word_list.add(word.lower())
                                        self.wordUrl_list.add(word.lower() + "  [GAP]")
                                    # If "Create singluar/plural words" option is checked, check if there is a singular/plural word to add
                                    if self.cbWordPlurals.isSelected():
                                        newWord = self.processPlural(word)
                                        if newWord != "" and len(newWord) > 3 and newWord.lower() not in self.lstStopWords:
                                            self.word_list.add(newWord)
                                            self.wordUrl_list.add(newWord + "  [GAP]")
                                            if self.cbWordLower.isSelected() and newWord != newWord.lower():
                                                self.word_list.add(newWord.lower())
                                                self.wordUrl_list.add(newWord.lower() + "  [GAP]")
                                            # If the original word was uppercase and didn't end in "S" but the new one does, also add the original word with a lower case "s"
                                            if self.cbWordLower.isSelected() and word.isupper() and word[-1:] != 'S' and newWord == word + 'S':
                                                self.word_list.add(word + 's')
                                                self.wordUrl_list.add(word + 's' + "  [GAP]")
        except Exception as e:
            if not self.flagCANCEL:
                self._stderr.println("getResponseWords 1")
                self._stderr.println(e)
                try:
                    self._stderr.println("The word that caused the error: " + word)
                except:
                    pass
            
    def getPathWords(self):
        """
        Get all words from path and if they do not contain file extension add them to the paramUrl_list
        Original contributor: @_pichik
        """
        self.txtDebugDetail.text = "getPathWords"
        if _debug:
            print("getPathWords started")
        try:
            url = self.currentReqResp.getRequestUrl()
            path = urlparse(url).path
            # Split the URL on /
            words = set(re.compile(r"[\:/?=\-&#]+", re.UNICODE).split(path) + path.split('/'))
            temp = []
            for x in words:
                temp.extend(x.split(","))
            words = set(temp)
            # Add the word to the parameter list, unless it has a . in it or is a number. or it is a single character that isn't a letter
            for word in words:
                if (
                    ("." not in word)
                    and (not word.isnumeric())
                    and not (len(word) == 1 and not word.isalpha())
                    and len(word) > 0
                ):
                    # If path words as Words are required, add to the list of words
                    if self.cbWordsEnabled.isSelected() and self.cbWordPaths.isSelected():
                        self.addWord(word.strip(), url)
                        
                    # If path words as parameters are required, add to the list of parameters
                    if self.cbParamsEnabled.isSelected() and self.cbIncludePathWords.isSelected():
                        self.addParameter(word.strip(), "Tentative", "PATH")
        except Exception as e:
            self._stderr.println("getPathWords 1")
            self._stderr.println(e)

    def checkIfCancel(self):
        if self.flagCANCEL:
            raise CancelGAPRequested("User pressed CANCEL GAP button.")

    def processPlural(self, originalWord):
        """
        A function that attempts to take a given English word, determine if its a plural or singular.
        If a plural, then return a new word as singular. If a singular, then return a new word as plural.
        IMPORTANT: This is prone to error as the english language has many exceptions to rules!
        """
        self.txtDebugDetail.text = "processPlural: "+originalWord
        try:
            newWord = ""
            word = originalWord.strip().lower()
            
            # Process Plurals and get a new word for singular
            
            # If word is over 30 characters long 
            # OR contains numbers and is over 10 characters long
            # OR ends in "ous"
            # then there will not be a new word
            if len(word) > 30 or (any(char.isdigit() for char in word) and len(word) > 10) or word[-4:] == "ous":
                newWord = ""
            # If word ends in "xes", "oes" or "sses" then remove the last "es" for the new word
            elif word[-3:] in ["xes","oes"] or word[-4:] == "sses":
                newWord = originalWord[:-2]
            # If word ends in "ies"
            elif word[-3:] == "ies":
                # If there is 1 letter before "ies" then the new word will just end "ie"
                if len(word) == 4:
                    if originalWord.isupper():
                        newWord = originalWord[1]+"IE"
                    else:
                        newWord = originalWord[1]+"ie"
                else: # the new word will just have "ies" replaced with "y"
                    if originalWord.isupper():
                        newWord = originalWord[:-3]+"Y"
                    else: 
                        newWord = originalWord[:-3]+"y"
            # If the word ends in "s" and isn't proceeded by "s" then the new word will have the last "s" removed
            elif word[-1:] == "s" and word[-2:-1] != "s":
                newWord = originalWord[:-1]
                
            # Process Singular and get a new word for plural
            
            # If word ends in "x","o" or "ss" then add "es" for the new word
            elif word[-1:] in ["x","o"] or word[-2:] == "ss":
                if originalWord.isupper():
                    newWord = originalWord+"ES"
                else:
                    newWord = originalWord+"es"
            # If word ends in "y" and isn't proceeded by a vowel, then replace "y" with "ies" for new word
            elif word[-1:] == "y" and word[-2:-1] not in ["a","e","i","o","u"]:
                if originalWord.isupper():
                    newWord = originalWord[:-1]+"IES"
                else:
                    newWord = originalWord[:-1]+"ies"    
            # If word ends in "o" and not prefixed by a vowel, then add "es" to get a new plural
            elif word[-1:] == "o" and word[-2:-1] not in ["a","e","i","o","u"]:
                if originalWord.isupper():
                    newWord = originalWord[:-1]+"ES"
                else:
                    newWord = originalWord[:-1]+"es"    
            # Else just add an "s" to get a new plural word
            else: 
                if originalWord.isupper():
                    newWord = originalWord+"S"
                else:
                    newWord = originalWord+"s"
            return newWord
        except Exception as e:
            self._stderr.println("processPlural 1")
            self._stderr.println(e)

    def addLink(self, url, origin=""):
        """
        Add a link, and prefix if necessary
        """
        self.txtDebugDetail.text = "addLink: "+url

        # If the "Include relative links?" option was not selected, and the link starts with ./ or ../ then don't add
        relativeUrl = False
        if (url.startswith("./") or url.startswith("../")):
            relativeUrl = True
        if not self.cbRelativeLinks.isSelected() and relativeUrl:
            return

        try:
            # If the link contains any non ASCII characters, then url encode them
            try:
                url.encode("ascii")
            except:
                try:
                    url = urllib.quote(url.encode('utf8',safe=':/'))
                    url = url.replace('%C3%83%C2%82%C3%82%C2%A0',' ').strip()
                except:
                    url = ""
            try:
                origin.encode("ascii")
            except:
                try:
                    origin = urllib.quote(origin.encode('utf8',safe=':/'))
                    origin = origin.replace('%C3%83%C2%82%C3%82%C2%A0',' ').strip()
                except:
                    origin = ""

            if url != '':
                allUrls = set()
                # Get the netloc of the url and if blank, add the prefix
                try:
                    result = urlparse(url)

                    if result.netloc == "":
                            
                        # If the "Include un-prefixed links" option is checked,add the original first
                        if self.cbUnPrefixed.isSelected():
                            # Add the link and origin to the list
                            self.link_list.add(url)
                            self.linkUrl_list.add(url + "  [" + origin + "]")
                                
                        # If the Link Prefix option is checked, then prefix if the link doesn't have a domain
                        if self.cbLinkPrefix.isSelected() or self.cbLinkPrefixScope.isSelected():
                            
                            # If the url doesn't start with a / then prefix it first, unless it is a relative url
                            if url[:1] != "/" and not relativeUrl:
                                url = "/" + url
                            
                            if self.cbLinkPrefix.isSelected():
                                
                                # Prefix each entry separated with a ;
                                for link in self.inLinkPrefix.text.split(";"):
                                    if relativeUrl:
                                        allUrls.add(link + "/" + url)
                                    else:
                                        allUrls.add(link + url)
                                        
                            # If specified to use targets, and the run context was Site Map tree, then add for all of those
                            if self.cbLinkPrefixScope.isSelected(): # and self.context.getInvocationContext() == 4:
                                
                                # Prefix with each root    
                                for prefix in self.allScopePrefixes:
                                    if relativeUrl:
                                        prefix = prefix + "/"
                                    allUrls.add(prefix + url)
                        else:               
                            allUrls.add(url)
                    else:
                        allUrls.add(url)

                    # Add all necessary prefixes
                    for u in allUrls:
                        self.checkIfCancel()
                        u = self.removeStdPort(u)
                        
                        # Add the link and origin to the list
                        self.link_list.add(u)
                        self.linkUrl_list.add(u + "  [" + origin + "]")
                        # Add to In Scope lists if the URL is in scope
                        try:
                            if self.isLinkInScope(u):
                                self.linkInScope_list.add(u)
                                self.linkUrlInScope_list.add(u + "  [" + origin + "]")
                        except Exception as e:
                            self._stderr.println("addLink 2")
                            self._stderr.println(e)
                
                except Exception as e:
                    if _debug:
                        self._stderr.println("addLink 3: "+url)
                        self._stderr.println(e)
                       
        except Exception as e:
            self._stderr.println("addLink 1")
            self._stderr.println(e)
    
    def getSusVulnTypes(self, param):
        """
        Determine the vulnerability types of the "Sus" parameter passed
        """
        self.txtDebugDetail.text = "getSusVulnTypes: "+param
        
        types = ""
        typesMin = ""
        if param in SUS_OPENREDIRECT:
            types = types + "Open Redirect, "
            typesMin = typesMin + "OR, "
        if param in SUS_DEBUG:
            types = types + "Active Debugging, "
            typesMin = typesMin + "DEBUG, "
        if param in SUS_XSS:
            types = types + "Cross-site Scripting (XSS), "
            typesMin = typesMin + "XSS, "
        if param in SUS_IDOR:
            types = types + "Insecure Direct Object Reference (IDOR), "
            typesMin = typesMin + "IDOR, "
        if param in SUS_FILEINC:
            types = types + "File Inclusion, "
            typesMin = typesMin + "LFI/RFI, "
        if param in SUS_CMDI:
            types = types + "OS Command Injection, "
            typesMin = typesMin + "CMDi, "
        if param in SUS_SQLI:
            types = types + "SQL Injection (SQLi), "
            typesMin = typesMin + "SQLi, "
        if param in SUS_SSRF:
            types = types + "Server-side Request Forgery (SSRF), "
            typesMin = typesMin + "SSRF, "
        if param in SUS_SSTI:
            types = types + "Server-side Template Injection (SSTI), "
            typesMin = typesMin + "SSTI, "
        if param in SUS_MASSASSIGNMENT:
            types = types + "Mass Assignment, "
            typesMin = typesMin + "MASS-ASSIGN, "
        return types.rstrip(", "), typesMin.rstrip(", ")
            
    def checkSusParams(self, param, confidence, context):
        """
        Create a Burp Issue for a suspect paramater, and also write to the extension output
        """
        self.txtDebugDetail.text = "checkSusParams: "+param
        try:
            # Only check if the parameter is less than 20 characters long and contains nothing other than 
            # letters, numbers, dash and under score
            if len(param) < 20 and self.REGEX_SUSPARAM.search(param):
                
                origin = self.currentReqResp.getRequestUrl()
                
                # Determine the vulns the param is for
                vulnTypes, minVulnTypes = self.getSusVulnTypes(param)

                # If a sus parameter was found...
                if not self.flagCANCEL and vulnTypes != '':
            
                    self.paramSus_list.add(param + "  [" + minVulnTypes + "]")
                    self.paramSusUrl_list.add(param + "  [" + origin + "]")
                    
                    # If the report sus param option is checked then report as issue and write to extension output
                    if self.cbReportSusParams.isSelected():
                        
                        # Create issue if NOT Burp Communiyty Edition
                        if not self.isBurpCommunity:
                            try:
                                createIssue = True
                                
                                # Determine the context detail and whether to create the issue
                                paramIssue = param+":"+origin
                                if context == "BURP":
                                    contextDetail = "The parameter was identified in the Request by Burp and reported by GAP.<br><br>"
                                elif context == "REQUEST":
                                    contextDetail = "The parameter was identified in the Request by GAP.<br><br>"
                                    self.susParamIssue.add(paramIssue)
                                elif context == "RESPONSE":
                                    contextDetail = "The potential parameter was identified in the Response by GAP.<br><br>"
                                    self.susParamIssue.add(paramIssue)
                                elif context == "PATH":
                                    contextDetail = "The potential parameter was identified by GAP because the <b><i>Include URL path words</i></b> option was selected.<br><br>"
                                    if paramIssue not in self.susParamIssue:
                                        self.susParamIssue.add(paramIssue)
                                    else:
                                        createIssue = False
                                elif context == "RESPLINKS":
                                    contextDetail = "The potential parameter was identified by GAP because the <b><i>Params from links found</i></b> option was selected.<br><br>"
                                    if paramIssue not in self.susParamIssue:
                                        self.susParamIssue.add(paramIssue)
                                    else:
                                        createIssue = False
                                else:
                                    contextDetail = "<br>"
                                
                                detail = 'The parameter <b>' + param + '</b> was found. This parameter is worthy of further investigation as it is often associated with the following vulnerability type(s): <b>' + vulnTypes + '</b><br>' + contextDetail
                                
                                # Look for matches of the parameter string
                                #matchesReq = self.getMatches(self.currentReqResp.getRequest(), param)
                                #matchesResp = self.getMatches(self.currentReqResp.getResponse(), param)
                                
                                # Create a scan issue
                                httpmessage = self.currentReqResp.getMessage()
                                if createIssue:
                                    self.createIssue(
                                        #http_message = self._callbacks.applyMarkers(httpmessage, matchesReq, matchesResp),
                                        http_message = httpmessage,
                                        issue_detail=detail,
                                        confidence=confidence,
                                    )
                                
                            except Exception as e:
                                if _debug:
                                    self._stderr.println("checkSusParams 2")
                                    self._stderr.println(str(e))
                                # If an error occurred, we cannot raise Issues in Burp so assume Community Edition
                                self.isBurpCommunity = True
                                pass
                        
                        # If Burp Community Edition then write the issue to the extension output if it hasn't been output already
                        if self.isBurpCommunity:
                            try:
                                detail = "Sus Parameter (" + minVulnTypes + "): " + param + "  [" + origin.split("?",1)[0] + "]"
                                if detail not in self.susParamText:
                                    self.susParamText.add(detail)
                                    print(detail)
                            except Exception as e:
                                self._stderr.println("checkSusParams 3")
                                self._stderr.println(str(e))
            
        except Exception as e:
            self._stderr.println("checkSusParams 1")
            self._stderr.println(str(e))
    
    def getMatches(self, httpmessage, match):
        """
        Helper method to search a response for occurrences of a literal match string
        and return a list of start/end offsets
        """
        self.txtDebugDetail.text = "getMatches"
        matches = []
        
        try:
            if httpmessage:
                start = 0
                reslen = len(httpmessage)
                matchlen = len(match)
                while start < reslen:
                    start = self._helpers.indexOf(httpmessage, match, True, start, reslen)
                    if start == -1:
                        break
                    matches.append(array('i', [start, start + matchlen]))
                    start += matchlen
        except Exception as e:
            self._stderr.println("getMatches 1")
            self._stderr.println(e)
            
        return matches
    
    def addParameter(self, param, confidence="", context=""):
        """
        Determine whether to add a parameter to the parameter list, and also to the word list depending on ticked options
        """
        self.txtDebugDetail.text = "addParameter: "+param
        try:
            # If the parameter contains any non ASCII characters, then url encode them
            try:
                param.encode("ascii")
            except:
                try:
                    param = urllib.quote(param.encode('utf8'))
                except:
                    param = ""
                    
            if param != "":
                # If the parameter has a ? in it then just get the part after the ?, unless the ? is at the end
                try:
                    param = param.split("?")[1]
                except:
                    param = param.split("?")[0]
                                
                # If the origin contains any non ASCII characters, then url encode them
                origin = self.currentReqResp.getRequestUrl()
                try:
                    origin.encode("ascii")
                except:
                    try:
                        origin = urllib.quote(origin.encode('utf8'))
                    except:
                        origin = "UNKNOWN"
                
                # Make sure any square brackets are decoded if there are in the parameter and encoded
                param = param.replace("%5b","").replace("%5B","").replace("%5d","").replace("%5D","")

                # If the parameter has any backslashes, forward slashes, quot;, apos; or amp; in, then remove them
                param = param.replace('\\', '').replace('/', '').replace('quot;','').replace('apos;','').replace('amp;','')
                
                # Add the param and origin to the list if the param does not contain at least 1 character that is a letter, number or _ 
                if param != "" and self.REGEX_PARAM.search(param) is not None:
                    
                    # Check if it is a sus parameter and raise scan issue if it is enabled
                    self.checkSusParams(param, confidence, context)
                    
                    #origin = self.removeStdPort(origin)
                    self.param_list.add(param)
                    self.paramUrl_list.add(param + "  [" + origin + "]")

                    # If the Words option is checked and the Include parameters is also checked, add the parameter to the word list
                    if self.cbWordsEnabled.isSelected() and self.cbWordParams.isSelected():
                        self.addWord(param, origin)

        except Exception as e:
            self._stderr.println("addParameter 1")
            self._stderr.println(e)
    
    def sanitizeWord(self, word):
        """
        URL encode any unicode characters in the word and also remove any unwanted characters
        """
        self.txtDebugDetail.text = "sanitizeWord: "+word
        try:
        # If the word contains any non ASCII characters, then url encode them
            try:
                word.encode("ascii")
            except:
                try:
                    word = urllib.quote(word.encode('utf-8'))
                except:
                    word = ""
            
            if word != '':
                word = self.REGEX_WORDSUB.sub('', word)
            
            return word
        except Exception as e:
            self._stderr.println("sanitizeWord 1")
            self._stderr.println(e)
            
    def addWord(self, word, origin):
        """
        Determine whether to add a word to the wordlist depending on ticked options
        """
        self.txtDebugDetail.text = "addWord: "+word
        try:
            include = True
            
            try:
                origin.encode("ascii")
            except:
                try:
                    origin = urllib.quote(origin.encode('utf8'))
                except:
                    origin = ""
                    
            word = self.sanitizeWord(word)
            
            # Check it is a minimum of 3 characters long
            if len(word.strip()) < 3:
                include = False
                
            # Check if digits
            elif not self.cbWordDigits.isSelected() and re.search(r'\d', word):
                include = False
            
            # Check the word isn't in the Stopword list
            elif word.lower() in self.lstStopWords:
                include = False
                
            # Check word length
            try:
                if include and len(word.strip()) > int(self.inWordsMaxlen.text):
                    include = False
            except:
                pass
                
            # Add the word to the list if it passed the tests
            if include:
                #origin = self.removeStdPort(origin)
                self.word_list.add(word.strip())
                self.wordUrl_list.add(word.strip() + "  [" + origin + "]")
                
                # Add a plural or singluar version of the word if required
                if self.cbWordPlurals.isSelected():
                    plural = self.processPlural(word)
                    if plural != "":
                        self.word_list.add(plural)
                        self.wordUrl_list.add(plural + "  [GAP]")
                
        except Exception as e:
            self._stderr.println("addWord 1")
            self._stderr.println(e)
           
    def createIssue(self, http_message, issue_detail, confidence='Certain'):
        """
        Create a Burp issue if one has not been raised already. 
        Each issue is assigned a GAP signature hash and if it exists in the local collection we won't create again.
        If it doesn't exist in the local collection then we search Burps Scan Issues and then add to local collection if we find it.
        No excpetion handling exists in this function because we want the error raised up, to determine whether to output the issue details to the extension output instead of raising an Issue.
        """
        self.txtDebugDetail.text = "createIssue: "+issue_detail
        custom_issue = CustomIssue(
            HTTPMessage=http_message,
            IssueDetail=issue_detail,
            Severity='Low',
            Confidence=confidence,
        )

        # If the issue has already been seen since GAP was loaded then just return,
        # else add it to the list of raised issue signatures
        if custom_issue.Signature in self.raisedIssues:
            return
        else:
            self.raisedIssues.add(custom_issue.Signature)
        
        # Check if the current issue already exists in Burps scan issues    
        rawUrl = http_message.url
        url = rawUrl.getProtocol()+"://"+rawUrl.getHost()+rawUrl.getPath()
        for issue in self._callbacks.getScanIssues(url):
            self.checkIfCancel()
            # If a match was found, addd it to the local collection so we don't have to keep iterating through Burps scan collection because it can be very slow
            signature = custom_issue.isDuplicate(issue)
            if signature != "":
                self.raisedIssues.add(signature)
                if _debug:
                    print('Duplicate issue: {}'.format(custom_issue.IssueDetail))
                return
        self._callbacks.addScanIssue(custom_issue)
            
class CancelGAPRequested(Exception):
    pass

class ReqResp():
    REGEX_CONTENTTYPE = re.compile(r"Content-Type:[^\n|$]*", re.IGNORECASE)
    REGEX_PORT80 = re.compile(r":80[^0-9]")
    REGEX_PORT443 = re.compile(r":443[^0-9]")
    REGEX_PORTSUB80 = re.compile(r":80")
    REGEX_PORTSUB443 = re.compile(r":443")
        
    def __init__(self, http_message, helpers, stderr):
        try:
            self.REGEX_CONTENTTYPE = re.compile(r"Content-Type:[^\r|\n|$]*", re.IGNORECASE)
            self.httpMessage = http_message
            self.httpRequest = http_message.getRequest()
            self.httpResponse = http_message.getResponse()
            if self.httpRequest:
                self.request = helpers.analyzeRequest(self.httpRequest)
                url = self.httpMessage.getUrl().toString()
                if url.find(":443") > 0:
                    if url.startswith("https:") and self.REGEX_PORT443.search(url) is not None:
                        url = self.REGEX_PORTSUB443.sub("", url, 1)
                elif url.find(":80") > 0:
                    if url.startswith("http:") and self.REGEX_PORT80.search(url) is not None:
                        url = self.REGEX_PORTSUB80.sub("", url, 1)
                self.requestUrl = url
                self.requestParams = self.request.getParameters()[0:]
                resquestString = helpers.bytesToString(self.httpRequest)
                bodyOffset = self.request.getBodyOffset()
                self.requestBody = resquestString[bodyOffset:]    
            else:
                self.request = None
                self.requestUrl = ""
                self.requestParams = ""
                self.requestBody = ""
                
            if self.httpResponse:
                self.response = helpers.analyzeResponse(self.httpResponse)
                self.responseString = helpers.bytesToString(self.httpResponse)
                bodyOffset = self.response.getBodyOffset()
                self.responseHeaders = self.responseString[:bodyOffset]
                self.responseBody = self.responseString[bodyOffset:]   
                try:
                    mime = self.response.getStatedMimeType()
                except:
                    mime = ""
                self.responseMIMEType = mime.upper()
                try:
                    contentType = str(self.REGEX_CONTENTTYPE.search(self.responseHeaders).group())
                    # If content-type is in format like "text/plain; charset=utf-8", then just select the first part
                    contentType = contentType.strip().split(" ")[1].split(";")[0]
                except:
                    contentType = ""
                self.responseContentType = contentType.strip()
            else:
                self.response = None
                self.responseString = ""
                self.responseHeaders = None
                self.responseBody = ""
                self.responseMIMEType = ""
                self.responseContentType = ""
        except Exception as e:
            stderr.println("ReqResp.__init__ 1")
            stderr.println(e)
        
    def isRequest(self):
        if self.httpRequest:
            return True
        else:
            return False
        
    def isResponse(self):
        if self.httpResponse:
            return True
        else:
            return False
        
    def getMessage(self):
        return self.httpMessage
                        
    def getRequestUrl(self):
        return self.requestUrl
    
    def getRequestBody(self):
        return self.requestBody
    
    def getRequestParams(self):
        return self.requestParams
    
    def getResponseBody(self):
        return self.responseBody

    def getResponseHeaders(self):
        return self.responseHeaders
    
    def getResponseContentType(self):
        return self.responseContentType
    
    def getResponseMIMEType(self):
        return self.responseMIMEType
    
class CustomKeyListener(KeyListener):
    """
    A custom event listener used for the "Apply/Clear Filter" button
    """

    def __init__(self, button):
        self.button = button

    def keyTyped(self, e=None):

        # Re-enable the "Apply filter" button
        if ord(e.keyChar) != 10:

            # Clear the current filter
            if self.button.text.startswith("Clear"):
                self.button.doClick()

            # Set the filter back to Apply
            self.button.setText("Apply filter")
            self.button.setEnabled(True)

    def keyPressed(self, e=None):
        # If ENTER pressed and the button is enabled, click it!
        if e.keyCode == 10 and self.button.isEnabled():
            self.button.doClick()

    def keyReleased(self, e=None):
        return

class CustomIssue(IScanIssue):
    """
    A Class used to create a custom issue in Burp 
    """
    def __init__(self, HTTPMessage, IssueName='[GAP] Sus Parameter', IssueDetail=None, IssueBackground="From research on \"suspect\" parameters by @jhaddix and @G0LDEN_infosec, 2023.", RemediationDetail=None, RemediationBackground=None, Severity='High', Confidence='Tentative'):

        self.HttpMessages=[HTTPMessage] # list of HTTP Messages
        self.HttpService=HTTPMessage.getHttpService() # HTTP Service
        self.Url=HTTPMessage.getUrl() # Java URL
        self.IssueType = 134217728 # always "extension generated"
        self.IssueName = IssueName # String
        self.IssueDetail = IssueDetail # String or None
        self.IssueBackground = IssueBackground # String or None
        self.RemediationDetail = RemediationDetail # String or None
        self.RemediationBackground = RemediationBackground # String or None
        self.Severity = Severity # "High", "Medium", "Low", "Information" or "False positive"
        self.Confidence = Confidence # "Certain", "Firm" or "Tentative"
        self.Signature = self._signIssue()
    
    def issuehash(self, text):
        """
        Generate a hash value to sign the issue. This is used to avoid duplicates
        """
        hash=0
        for ch in text:
            hash = (hash*281 ^ ord(ch)*997) & 0xFFFFFFFFFFF
        return str(hash) 

    def _signIssue(self):  

        sig = self.issuehash(self.IssueDetail+self.Severity+self.Confidence)
        block = '[GAP:{}]'.format(sig)
        self.IssueDetail += block
        return sig

    def isDuplicate(self, issue):

        if issue.issueDetail is not None:
            m = re.search(r'\[GAP:([^\]]+)\]', issue.issueDetail)
            if m and m.group(1) == self.Signature:
                return m.group(1)
        return ""

    def getHttpMessages(self):

        return self.HttpMessages

    def getHttpService(self):
        return self.HttpService

    def getUrl(self):
        
        return self.Url

    def getConfidence(self):

        return self.Confidence

    def getIssueBackground(self):

        return self.IssueBackground

    def getIssueDetail(self):

        return self.IssueDetail

    def getIssueName(self):

        return self.IssueName

    def getIssueType(self):

        return self.IssueType

    def getRemediationBackground(self):

        return self.RemediationBackground

    def getRemediationDetail(self):

        return self.RemediationDetail

    def getSeverity(self):

        return self.Severity
