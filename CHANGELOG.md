## Changelog

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
