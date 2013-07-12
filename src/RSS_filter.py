#!/usr/bin/env python2

"""
RSS Filter

Usage:
  RSS-filter
  RSS-filter -e | --edit
  RSS-filter -l | --list
  RSS-filter -h | --help

Options:
  -h --help    Show this message.
  -e --edit    Edit the filters with your default editor.
  -l --list    List feed titles.
"""

import os
import errno
import stat
from cStringIO import StringIO
import subprocess
import sys
import re
import logging
from collections import OrderedDict

import requests
import configobj
import validate
import appdirs
import docopt
import demjson


class Feedbin:
    """
    A partial Feedbin API client + some application specific utility functions and the filtering logic.
    """

    API_URL = "https://api.feedbin.me/v2/{}.json"
    to_be_read = []

    def __init__(self, username, password):
        self.session = requests.Session()
        self.session.auth = (username, password)

    def _get(self, endpoint, params=None, JSON=True):
        """
        Make a GET request to the Feedbin API and return JSON.
        """
        r = self.session.get(self.API_URL.format(endpoint), params=params)
        if not r.ok:
            r.raise_for_status()

        if not JSON:
            return r
        else:
            return r.json()

    def _mark_as_read(self):
        """
        Mark-as-read the entries with IDs listed in self.to_be_read.
        """
        # TODO: split entries into groups of <= 1000
        r = self.session.delete(self.API_URL.format("unread_entries"),
                                data=demjson.encode({"unread_entries": self.to_be_read}),
                                headers={"Content-Type": "application/json; charset=utf-8"})
        if not r.ok:
            r.raise_for_status()

    def _subscription_list(self):
        """
        Return an OrderedDict mapping tags to their contained feeds (sorted by tag name and feed
        title, respectively). Non-tagged feeds are put in a tag called "<Untagged>" in the last position.
        """
        subs = self._get("subscriptions")
        taggings = self._get("taggings")

        subs_list = {tag: [] for tag in set(tagging[u"name"] for tagging in taggings)}
        subs_list = OrderedDict(sorted(subs_list.items()))
        subs_list["<Untagged>"] = []

        for sub in subs:
            found = False
            for tagging in taggings:
                if tagging[u"feed_id"] == sub[u"feed_id"]:
                    subs_list[tagging[u"name"]].append(sub)
                    found = True
                    break
            if not found:
                subs_list["<Untagged>"].append(sub)

        for tag in subs_list:
            subs_list[tag] = sorted(subs_list[tag], key=lambda sub: sub[u"title"])

        return subs_list

    def _count_unread(self, feed):
        """Return the unread count for the given feed."""
        if not self.unread:
            self._retrieve_unread_entries()

        unread_entries = [entry for entry in self.unread if entry[u"feed_id"] == feed[u"feed_id"]]
        return len(unread_entries)

    def tag_list(self):
        """
        Return an OrderedDict mapping tags to a list of tuples containing the unread count and
        title for each feed in the tag.
        """

        print u"Retrieving unread entries..."
        self._retrieve_unread_entries()
        subs_list = self._subscription_list()

        feeds = {tag: [(self._count_unread(feed), feed[u"title"]) for feed in subs_list[tag]]
                 for tag in subs_list if tag != u"<Untagged>"}
        untagged = {tag: [(self._count_unread(feed), feed[u"title"]) for feed in subs_list[tag]]
                    for tag in subs_list if tag == u"<Untagged>"}

        sorted_feeds = sorted(feeds.items())
        sorted_feeds.extend(untagged.items())

        return OrderedDict(sorted_feeds)

    def _retrieve_unread_entries(self):
        """
        Retrieve all unread entries.
        """

        r = self._get("entries", params={"read": "false"}, JSON=False)
        entries = r.json()

        while True:
            # Feedbin returns link headers under "links", but requests expects them to be under "link"
            r.headers["link"] = r.headers["links"]
            if not r.links.get("next", None):
                break

            # this is easier than using the entire URL directly
            r = self._get("entries", params=requests.utils.urlparse(r.links["next"]["url"])[4], JSON=False)
            entries.extend(r.json())

        self.unread = entries

    def _apply_filter(self, feed, patterns):
        """
        Apply filters to a feed. Returns the number of items marked-as-read.
        """

        entries = [entry for entry in self.unread if entry[u"feed_id"] == feed[u"feed_id"]]
        if not entries:
            # no unread entries
            return None

        print u"Searching \"{}\" for matching items...".format(feed[u"title"]),
        sys.stdout.flush()

        count = len(self.to_be_read)
        for pattern in patterns:
            regex = re.compile(pattern)
            for entry in entries:
                if regex.search(entry[u"title"]):
                    # TODO: remove entry from entries
                    self.to_be_read.append(entry[u"id"])

        return len(self.to_be_read) - count

    def apply_filters(self, filters):
        """
        Mark-as-read the items in the specified feeds matched by the specified filters.
        """

        feed_count = 0
        item_count = 0
        processed_feeds = set()

        try:
            print u"Retrieving subscribed feeds..."
            subs_list = self._subscription_list()
            print u"Retrieving unread items..."
            self._retrieve_unread_entries()
        except KeyboardInterrupt:
            exit("cancelled")

        print u"Applying filters..."

        universal_patterns = filters.get(u"*", [])

        for tag in subs_list:
            tag_has_matching_feeds = False
            for feed in subs_list[tag]:
                # get the applicable filters
                patterns = universal_patterns[:]
                try:
                    patterns.extend(filters[feed[u"title"]])
                except KeyError:
                    pass

                if not feed[u"feed_id"] in processed_feeds:
                    processed_feeds.add(feed[u"feed_id"])

                if not patterns:
                    # skip to next feed
                    continue

                # since there are applicable patterns, the current tag has at least one matching feed
                if not tag_has_matching_feeds:
                    tag_has_matching_feeds = True
                    print u"\n{}\n{}".format(tag, u"=" * len(tag))

                feed_count += 1
                items_found = self._apply_filter(feed, patterns)
                if items_found is not None:
                    print u"found {}.".format(items_found)
                    item_count += items_found

        if self.to_be_read:
            self._mark_as_read()

        return feed_count, item_count


def check_config(config_dir):
    try:
        os.makedirs(config_dir)
    except OSError as e:
        if e.errno == errno.EEXIST and os.path.isdir(config_dir):
            pass
        else:
            raise

    spec = """username = string\npassword = string"""
    config_spec = configobj.ConfigObj(StringIO(spec))
    config_path = os.path.join(config_dir, "settings.ini")
    config = configobj.ConfigObj(config_path, configspec=config_spec)
    valid = config.validate(validate.Validator())

    if valid is True:
        try:
            with open(os.path.join(config_dir, "filters.json")) as filters_file:
                filters_json = filters_file.read()
                try:
                    filters = demjson.decode(filters_json, encoding="utf8", strict=True, allow_comments=True)
                except demjson.JSONDecodeError as e:
                    filters = (False, e.pretty_description())
            return config, filters
        except IOError as e:
            if e.errno == errno.ENOENT:
                f = open(os.path.join(config_dir, "filters.json"), "w")
                f.write('{\n'
                        '    // comment\n'
                        '    "feed name": ["filter regexp", "another filter regexp"]\n'
                        '}\n')
                f.close()
            else:
                raise

    elif valid is False:
        config["username"] = raw_input("Feedbin username\n:  ")
        config["password"] = raw_input("Feedbin password\n:  ")

    try:
        config.write()
        os.chmod(config_path, stat.S_IRUSR | stat.S_IWUSR)  # mode -rw-------
        print "Config written successfully."
        exit(1)
    except Exception as e:
        print "{}\nConfig file was not written.".format(e)
        exit(2)


def edit_filters(filters, config_dir):
    """open the filters file with the default editor"""
    if filters is None:
        print "No filters specified."
    elif isinstance(filters, tuple) and filters[0] is False:
        print "Filters file is invalid: {}\n".format(filters[1])
    # else: "--edit" option was passed

    filters_path = os.path.join(config_dir, "filters.json")
    print "Opening filters file (\"{}\")...".format(filters_path)

    if sys.platform.startswith("darwin"):  # OSX
        subprocess.call(("open", filters_path))
    elif os.name == "nt":  # Windows
        os.startfile(filters_path)
    elif os.name == "posix":  # other *nix
        try:
            with open(os.devnull, "w") as fnull:
                retcode = subprocess.call(("xdg-open", filters_path), stderr=fnull)
            if retcode != 0:
                raise OSError
        except OSError:
            editor = os.environ["EDITOR"]
            subprocess.call((editor, filters_path))


def list_feeds(feedbin):
    """
    Print the user's subscribed feeds and their respective unread counts,
    separated by tag name and ordered alphabetically.
    """
    tags = feedbin.tag_list()

    col_width = max(len(str(unread_count)) for unread_count in
                    [feed[0] for tag in tags for feed in tags[tag]]) + 4

    for tag in tags:
        try:
            print "\n{}\n{}".format(tag, "=" * len(tag))
        except UnicodeEncodeError:
            print "\n{}\n{}".format(tag, "=" * len(tag)).encode("cp850", "backslashreplace")

        for feed in tags[tag]:
            try:
                print "".join(unicode(column).ljust(col_width) for column in feed)
            except UnicodeEncodeError:
                print "".join(unicode(column).ljust(col_width)
                              for column in feed).encode("cp850", "backslashreplace")


def main():
    args = docopt.docopt(__doc__)
    config_dir = appdirs.user_data_dir("RSS-filter", "U2Ft")
    config, filters = check_config(config_dir)
    logging.basicConfig(filename=os.path.join(config_dir, "RSS-filter.log"), level=logging.INFO,
                        datefmt="%Y-%m-%d %H:%M:%S", format="%(asctime)s: %(message)s")

    # silence requests.packages.urllib3's logging of every connection at level INFO
    requests_logger = logging.getLogger("requests.packages.urllib3")
    requests_logger.setLevel(logging.WARNING)

    if isinstance(filters, tuple) or args["--edit"]:
        edit_filters(filters, config_dir)
        exit(4)

    feedbin = Feedbin(config["username"], config["password"])

    if args["--list"]:
        list_feeds(feedbin)
        exit(0)

    feed_count, item_count = feedbin.apply_filters(filters)
    if feed_count == 1:
        if item_count == 1:
            logging.info("1 matching item was found in 1 matching feed.")
            print "\n1 matching item was found in 1 matching feed."
        else:
            logging.info("{} matching items were found in 1 matching feed.".format(item_count))
            print "\n{} matching items were found in 1 matching feed.".format(item_count)
    else:
        if item_count == 1:
            logging.info("1 matching item was found in {} matching feeds.".format(feed_count))
            print "\n1 matching item was found in {} matching feeds.".format(feed_count)
        else:
            logging.info("{} matching items were found in {} matching feeds.".format(item_count, feed_count))
            print "\n{} matching items were found in {} matching feeds.".format(item_count, feed_count)


if __name__ == "__main__":
    main()
