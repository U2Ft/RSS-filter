RSS Filter
==========

Marks-as-read Feedbin feed items that match a specified filter.

Services post Google Reader
---------------------------

Currently only Feedbin is supported, since that's what I'm now using.
However, I'm happy to add support for other services if there's any
interest (`@U2Ft <https://twitter.com/U2Ft>`__).

Installation
------------

::

    pip install git+git://github.com/U2Ft/RSS-filter.git

Upgrading
---------

-  delete the config file with Google Reader credentials from

**OSX** ``~/Library/Application Support/RSS-filter/settings.ini``

**Linux** ``~/.config/rss-filter/settings.ini``

**Windows** ``%LOCALAPPDATA%\U2Ft\RSS-filter\settings.ini``

-  upgrade with ``pip``

::

    pip install --upgrade git+git://github.com/U2Ft/RSS-filter.git

-  filters will remain intact

Usage
-----

::

    RSS Filter

    Usage:
      RSS-filter
      RSS-filter -e | --edit
      RSS-filter -h | --help
      RSS-filter -l | --list

    Options:
      -h --help    Show this message.
      -e --edit    Edit the filters with your default editor.
      -l --list    List feed titles.

Specify some filters, then run manually or write a cron job--something
like

::

    0 6,4 * * * RSS-filter > /dev/null

Run summaries are logged to a file in the config directory.

Filters
-------

The filters file is JSON. Comments are allowed. The format is \`\`\`js {
// Every feed "\*": ["regex"],

::

    // Specific feeds
    "feed title": ["regex"]

} \`\`\`

where ``regex`` is a `Python Regular
Expression <http://docs.python.org/2/library/re.html#regular-expression-syntax>`__.
Items in the named feed with titles that match the regex are marked as
read.

Filters for the feed title ``*`` are applied to every feed.

Note the irregular behaviour of backslash-escapes--in practice, repeat
them. E.g. to match a ``[`` in the item title, the regex should be
``"\\["``.

Watch out for HTML entities (e.g. ``&amp;``) in item and feed titles. If
a regex that should be matching isn't, that's probably why.
