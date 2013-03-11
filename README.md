# RSS Filter

Marks-as-read Google Reader feed items that match a specified filter.

## Installation

```
pip install git+git://github.com/U2Ft/RSS-filter.git
```

You'll need a [Google OAuth client ID](https://code.google.com/apis/console/b/0/?pli=1#access).

## Usage

```
RSS Filter

Usage:
  RSS-filter.py
  RSS-filter.py -e | --edit
  RSS-filter.py -h | --help
  RSS-filter.py -l | --list

Options:
  -h --help    Show this message.
  -e --edit    Edit the filters with your default editor.
  -l --list    List feed titles.
```

Specify some filters, then run manually or write a cron job--something like

```
0 6,4 * * * RSS-filter > /dev/null
```

Run summaries are logged to a file in the config directory.

## Filters

The filters file is JSON. Comments are allowed.
The format is 
```js
{
    // Every feed
    "*": ["regex"],

    // Specific feeds
    "feed title": ["regex"]
}
```

where `regex` is a [Python Regular Expression](http://docs.python.org/2/library/re.html#regular-expression-syntax).
Items in the named feed with titles that match the regex are marked as read.

Filters for the feed title `*` are applied to every feed.

Note the irregular behaviour of backslash-escapes--in practice, repeat them.
E.g. to match a `[` in the item title, the regex should be `"\\["`.

Watch out for HTML entities (e.g. `&amp;`) in item and feed titles. If a regex that should be matching isn't, that's probably why.

