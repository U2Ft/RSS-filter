#!/usr/bin/env python2

"""
RSS Filter

Usage:
  {0}
  {0} -e | --edit
  {0} -l | --list
  {0} -h | --help

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

import libgreader
import requests
import configobj
import validate
import appdirs
import docopt
import demjson


class GoogleReader:
    """A partial wrapper around libgreader."""

    def __init__(self, client_ID, client_secret, refresh_token):
        self.client_ID = client_ID
        self.client_secret = client_secret

        if refresh_token:
            self.refresh_token = refresh_token
            self.auth = self._authenticate()
            self.libgreader = libgreader.GoogleReader(self.auth)

    def _authenticate(self):
        payload = {"client_id": self.client_ID, "client_secret": self.client_secret,
                   "refresh_token": self.refresh_token, "grant_type": "refresh_token"}
        r = requests.post("https://accounts.google.com/o/oauth2/token", data=payload)

        try:
            access_token = r.json["access_token"]
        except KeyError:
            logging.CRITICAL("Couldn't authenticate with Google Reader.")
            print "Error. Couldn't authenticate with Google Reader."
            exit(3)

        auth = libgreader.OAuth2Method(self.client_ID, self.client_secret)
        auth.setRedirectUri("urn:ietf:wg:oauth:2.0:oob")
        auth.access_token = access_token

        return auth

    def get_refresh_token(self):
        auth = libgreader.OAuth2Method(self.client_ID, self.client_secret)
        auth.setRedirectUri("urn:ietf:wg:oauth:2.0:oob")
        auth_URL = auth.buildAuthUrl()

        params = {"format": "json", "url": auth_URL, "logstats": 0}
        r = requests.get("http://is.gd/create.php", params=params)
        if r.ok:
            auth_URL = r.json["shorturl"]

        print ("To authorize access to Google Reader, visit this URL "
               "and follow the instructions:\n\n{}\n").format(auth_URL)

        auth_code = raw_input("Enter verification code:  ")
        print
        payload = {"client_id": self.client_ID, "client_secret": self.client_secret, "code": auth_code,
                   "redirect_uri": "urn:ietf:wg:oauth:2.0:oob", "grant_type": "authorization_code"}
        r = requests.post("https://accounts.google.com/o/oauth2/token", data=payload)

        return r.json["refresh_token"]

    def user_info(self):
        return self.libgreader.getUserInfo()

    def subscription_list(self):
        """
        Return an OrderedDict mapping categories to their contained feeds, sorted by category label and feed
        title, respectively.
        """
        self.libgreader.buildSubscriptionList()
        categories = {cat: sorted(cat.getFeeds(), key=lambda f: f.title)
                      for cat in self.libgreader.getCategories()}
        return OrderedDict(sorted(categories.items(), key=lambda c: c[0].label))

    def category_list(self):
        """
        Return an OrderedDict mapping category labels to a list of tuples containing the unread count and
        title for each feed in the category. Categories and feeds are sorted alphabetically.
        """
        categories = self.subscription_list()
        feeds = {cat.label: [(feed.unread, feed.title) for feed in categories[cat]] for cat in categories}
        return OrderedDict(sorted(feeds.items()))

    def get_unread_items(self, feed):
        items = []
        while len(items) < feed.unread:
            if items:
                feed.loadMoreItems(excludeRead=True)
            else:
                feed.loadItems(excludeRead=True)
            items = [i for i in feed.getItems() if i.isUnread()]

        return items

    def apply_filters(self, filters):
        feed_count = 0
        item_count = 0
        self.auth.setActionToken()

        filtered_feeds = set()

        categories = self.subscription_list()
        print "Applying filters..."
        for category in categories:
            category_has_matching_feeds = False

            for feed in categories[category]:
                try:
                    patterns = filters[feed.title]
                    if feed.id in filtered_feeds:
                        raise ValueError
                    else:
                        filtered_feeds.add(feed.id)
                except KeyError:
                    pass  # no filter specified for this feed
                except ValueError:
                    pass  # this feed was in a previously-processed category
                else:
                    if not category_has_matching_feeds:
                        category_has_matching_feeds = True
                        print "\n{}\n{}".format(category.label, "=" * len(category.label))

                    print "Searching \"{}\" for matching items...".format(feed.title),
                    sys.stdout.flush()

                    feed_count += 1
                    items = self.get_unread_items(feed)
                    n = item_count

                    for pattern in patterns:
                        regex = re.compile(pattern)
                        for item in items:
                            if regex.search(item.title):
                                item_count += 1
                                item.markRead()

                    print "found {}.".format(item_count - n)

        return feed_count, item_count


def check_config(config_dir):
    try:
        os.makedirs(config_dir)
    except OSError as e:
        if e.errno == errno.EEXIST and os.path.isdir(config_dir):
            pass
        else:
            raise

    spec = """client_ID = string\nclient_secret = string\nrefresh_token = string"""
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
        config["client_ID"] = raw_input("Google OAuth Client ID\n:  ")
        config["client_secret"] = raw_input("Google OAuth Client Secret\n:  ")
        GR = GoogleReader(config["client_ID"], config["client_secret"], None)
        config["refresh_token"] = GR.get_refresh_token()

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


def list_feeds(reader):
    """
    Print the user's subscribed feeds and their respective unread counts,
    separated by category name and ordered alphabetically.
    """
    categories = reader.category_list()

    col_width = max(len(str(unread_count)) for unread_count in
                    [feed[0] for cat in categories for feed in categories[cat]]) + 4

    for cat in categories:
        try:
            print "\n{}\n{}".format(cat, "=" * len(cat))
        except UnicodeEncodeError:
            print "\n{}\n{}".format(cat, "=" * len(cat)).encode("cp850", "backslashreplace")

        for feed in categories[cat]:
            try:
                print "".join(unicode(column).ljust(col_width) for column in feed)
            except UnicodeEncodeError:
                print "".join(unicode(column).ljust(col_width)
                              for column in feed).encode("cp850", "backslashreplace")


def main():
    args = docopt.docopt(__doc__.format(sys.argv[0]))
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

    reader = GoogleReader(config["client_ID"], config["client_secret"], config["refresh_token"])

    if args["--list"]:
        list_feeds(reader)
        exit(0)

    feed_count, item_count = reader.apply_filters(filters)
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
