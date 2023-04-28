## Changelog

- v3.1

  - Changed

    - A small fix to ensure that if the `Prefix with selected Target(s)` option is checked that output links do not have `//` after the host

- v3.0

  - New

    - Add `Show origin endpoint` filter to Parameters and save as part of config when the **Save options** button is pressed.
    - If the `Auto save output to directory` option is checked, then files are written as follows:
      - Create a sub folder for each root in the target site that was selected in Site Map
      - Create a file in the main folder with the name of the Burp project and timestamp, e.g. if the project is called `target`, the files might be `target_20230416_133700_links.txt`, `target_20230416_133700_parans.txt` and `target_20230416_133700_words.txt` where `20230416` is the current date in `YYYYMMDD` format and `133700` is the current time in `HHMMSS` format. These files will contain what was found for ALL roots selected.
      - Within each sub folder, the files will only contain findings for that particular root. If there are no findings for a mode, then a file will not be created for that mode.
    - If the `Include common parameters` option is checked and the Parameter `Show origin endpoint` is checked, the common parameters are displayed and written to file with `[GAP]` instead of a Link where the parameter was found.

  - Changed
    - You can now select sub folders, or specific requests, from the Site Map to process with GAP.
    - The `Show origin endpoint` option for Parameters and Links, and the `In scope only` option are applied to what is displayed AND what is written to file.
    - If a link is found that has a different scheme than http or https, the `URL(link).getHost()` method returns blank. This previously resulted in the link not being checked if it was in scope and incorrectly included. This has been fixed.
    - Make changes to the functions that display links, parameters and words to improve speed and use less memory.
    - Parameters and words from path words were not correctly checked whether they are in scope or not. This has been fixed.
    - If a link has `\s` or `\S` in it, don't include as it's most likely a regex string, not a link.
    - If one mode finishes before others are, allow any filters to be used on the finished panels, even if the others aren't complete.
    - If Origin is written to the Links or Params file, only separate the URL and \[ORIGIN\] with one space. Two spaces are used in the UI to make it easier to view.
    - Suppress warnings from the beautifulsoup4 library.

- v2.9

  - New

    - Add new checkbox "Prefix with selected Target(s)". If selected, any links found that don't have a domain will be prefixed with each target root that was selected in the Site Map when running GAP.
    - Added some tool tips

  - Changed

    - The "Prefix with links(s)" (was previously called "Link Prefix") can now have multiple links separated by a semicolon. If a schema is left off a link then it will be added on. If the field has invalid values, the text will be displayed in red, indicating it needs to be fixed. Links will be output with each prefix

- v2.8

  - New

    - When GAP is searching, the tab caption will say **GAP\*** instead of **GAP**. Also, when complete, and the user is not on the GAP tab, the title will show **GAP** in Burp Orange. The text is reset to default colour when another target is searched of if any options are changed.

- v2.7

  - New

    - Sanitize words before adding them to the list, e.g. remove `"`,`%22`, `<`, `%3c`, etc.
    - If a potential parameter has a `?` in it, then just get the value after the `?` as the parameter

  - Changed

    - Add more parameter names to the `COMMON_PARAMS` constant.

- v2.6

  - Changed

    - For Parameters, Links and Words, check if the string being added contains any unicode characters. If it does, then URL encode the characters before adding them to the lists to display and output. This change prevents a number of errors output and also prevents Burp from freezing with certain conditions.

- v2.5

  - New

    - Get more potential parameters from responses based on patterns like `?param=` and `&param=`

  - Changed

    - Only get parameters from responses that don't have content types of file types in the given exclusions.

- v2.4

  - New

    - Add `FILEEXT_EXCLUSIONS` constant that are file extensions we do not want to check for links. If a content type cannot be found then the extension in a URL (if there is one) will be used to check against this list and exluded if necessary.

  - Changed
    - Add these content types to the `DEFAULT_CONTENTTYPE_EXCLUSIONS` constant, and the `contentExclude` section of `config.yml`: `application/zip,application/x-zip-compressed,application/x-msdownload,application/x-apple-diskimage,application/x-rpm,application/vnd.debian.binary-package`

- v2.3

  - New
    - Re-introduce the option of viewing parameters in a concatenated query string. There is now a check box below the parameter list that can be used to switch views.

- v2.2

  - Changed
    - Encode parameters, links and words to ASCII before adding them to lists so that no unicode errors occur when displaying them.
    - Change error message for bs4 not installed to include a link to the installation instructions on github.

- v2.1

  - Changed
    - Minor bug fix and improvement

- v2.0

  - New

    - Add **Words** mode that will produce a target specific wordlist.
    - Add options for **Words** mode.
    - Add an option to provide a prefix for links that are found that don't have a domain.
    - Add `requirements.txt` file for external modules that are needed for GAP.
    - Add a progress bar to show how many requests per root are being processed.
    - Add a **Buy Me a Coffee** button.
    - Add `banner.png` to use on extension tab.

  - Changed
    - Sooooo many minor bug fixes to mention :)
    - Allow user to select a sub folder of a site mop root, or even just one endpoint to process.
    - Get links from the response headers too. It should have been doing this already, but wasn't.
    - When **Include site map endpoints in link list** option is selected, return the full URL, not just the path.
    - Fixed bug when saving files on Linux.
