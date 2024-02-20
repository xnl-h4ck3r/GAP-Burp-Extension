<center><img src="https://raw.githubusercontent.com/xnl-h4ck3r/GAP-Burp-Extension/main/GAP/images/title.png"></center>

## About - v4.7

This is an evolution of the original getAllParams extension for Burp. Not only does it find more potential parameters for you to investigate, but it also finds potential links to try these parameters on, and produces a target specific wordlist to use for fuzzing.
The full Help documentation can be found [here](https://github.com/xnl-h4ck3r/burp-extensions/blob/main/GAP%20Help.md) or from the Help icon on the GAP tab.

## TL;DR

### Installation

1. Visit [Jython Offical Site](https://www.jython.org/download), and download the latest stand alone JAR file, e.g. `jython-standalone-2.7.3.jar`.
2. Open Burp, go to **Extensions** -> **Extension Settings** -> **Python Environment**, set the **Location of Jython standalone JAR file** and **Folder for loading modules** to the directory where the Jython JAR file was saved.
3. On a command line, go to the directory where the jar file is and run `java -jar jython-standalone-2.7.3.jar -m ensurepip`.
4. Download the `GAP.py` and `requirements.txt` from this project and place in the same directory.
5. Install Jython modules by running `java -jar jython-standalone-2.7.3.jar -m pip install -r requirements.txt`.
6. Go to the **Extensions** -> **Installed** and click **Add** under **Burp Extensions**.
7. Select **Extension type** of **Python** and select the **GAP.py** file.

### Using

1. Just select a target in your Burp scope (or multiple targets), or even just one subfolder or endpoint, and choose extension **GAP**:

<center><img src="https://raw.githubusercontent.com/xnl-h4ck3r/GAP-Burp-Extension/main/GAP/images/run.png"></center>

Or you can right click a request or response in any other context and select **GAP** from the **Extensions** menu.

2. Then go to the **GAP** tab to see the results:

<center><img src="https://raw.githubusercontent.com/xnl-h4ck3r/GAP-Burp-Extension/main/GAP/images/tab.png"></center>

## IMPORTANT Notes

If you don't need one of the modes, then un-check it as results will be quicker.

If you run GAP for one or more targets from the Site Map view, don't have them expanded when you run GAP... unfortunately this can make it a lot slower. It will be more efficient if you run for one or two target in the Site Map view at a time, as huge projects can have consume a lot of resources.

If you want to run GAP on one of more specific requests, do not select them from the Site Map tree view. It will be a lot quicker to run it from the Site Map Contents view if possible, or from proxy history.

It is hard to design GAP to display all controls for all screen resolutions and font sizes. I have tried to deal with the most common setups, but if you find you cannot see all the controls, you can hold down the `Ctrl` button and click the GAP logo header image to remove it to make more space.

The Words mode uses the `beautifulsoup4` library and this can be quite slow, so be patient!

## In Depth Instructions

Below is an in-depth look at the GAP Burp extension, from installing it successfully, to explaining all of the features.

**NOTE: This video is from 16th July 2023 and explores v3.X, so any features added after this may not be featured.**

[![GAP Burp Extension](https://img.youtube.com/vi/Os3bN0zUROA/0.jpg)](https://www.youtube.com/watch?v=Os3bN0zUROA)

## TODO

- Get potential parameters from the Request that Burp doesn't identify itself, e.g. XML, graphql, etc.
- Add an option to not add the `Tentaive` Issues, e.g. Parameters that were found in the Response (but not as query parameters in links found).
- Improve performance of the link finding regular expressions.
- Include the Request/Response markers in the raised Sus parameter Issues if I can find a way to not make performance really bad!
- Deal with other size displays and font sizes better to make sure all controls are viewable.
- If multiple Site Map tree targets are selected, write the files more efficiently. This can take forever in some cases.
- Use an alternative to `beautifulsoup4` that is faster to parse responses for Words.

Good luck and good hunting!
If you really love the tool (or any others), or they helped you find an awesome bounty, consider [BUYING ME A COFFEE!](https://ko-fi.com/xnlh4ck3r) ☕ (I could use the caffeine!)

🤘 /XNL-h4ck3r

<a href='https://ko-fi.com/B0B3CZKR5' target='_blank'><img height='36' style='border:0px;height:36px;' src='https://storage.ko-fi.com/cdn/kofi2.png?v=3' border='0' alt='Buy Me a Coffee at ko-fi.com' /></a>
