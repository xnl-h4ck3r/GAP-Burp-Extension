## Changelog

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
