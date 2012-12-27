#!/usr/bin/env python2

"""
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
"""

import os
import errno
import stat
from cStringIO import StringIO
import json
import subprocess
import sys
import re

import libgreader
import requests
import configobj
import validate
import appdirs
import docopt


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
        except KeyError as e:
            print "\n{}\n\n{}\n\nError. Couldn't parse access token.".format(e, r.text)
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
        self.libgreader.buildSubscriptionList()
        return self.libgreader.getSubscriptionList()

    def list_feeds(self):
        for feed in self.subscription_list():
            if feed.unread < 10000:
                yield u"({}){}{}".format(feed.unread, " " * (5 - len(str(feed.unread))), feed.title)
            else:
                yield u"({}) {}".format(feed.unread, feed.title)

    def get_unread_items(self, feed):
        items = []
        while len(items) < feed.unread:
            if items:
                feed.loadMoreItems()
            else:
                feed.loadItems()
            items = [i for i in feed.getItems() if i.isUnread()]

        return items

    def apply_filters(self, filters):
        feed_count = 0
        item_count = 0
        self.auth.setActionToken()

        for feed in self.subscription_list():
            try:
                patterns = filters[feed.title]
                print "Searching \"{}\" for matching items...".format(feed.title),
                sys.stdout.flush()

                feed_count += 1
                items = self.get_unread_items(feed)
                n = item_count

                for pattern in patterns:
                    for item in items:
                        regex = re.compile(pattern)
                        if regex.search(item.title):
                            item_count += 1
                            item.markRead()

                print "found {}.".format(item_count - n)
            except KeyError:
                pass

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
                try:
                    filters = json.load(filters_file)
                except ValueError as e:
                    if e.message == "No JSON object could be decoded":
                        filters = None
                    else:
                        filters = (False, e.message)
            return config, filters
        except IOError as e:
            if e.errno == errno.ENOENT:
                f = open(os.path.join(config_dir, "filters.json"), "w")
                f.write("""{\n    // "feed name": ["excluded string", "another excluded string"],\n}\n""")
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


def open_file(path):
    if sys.platform.startswith("darwin"):
        subprocess.call(("open", path))

    elif os.name == "nt":
        os.startfile(path)

    elif os.name == "posix":
        try:
            with open(os.devnull, "w") as fnull:
                retcode = subprocess.call(("xdg-open", path), stderr=fnull)
            if retcode != 0:
                raise OSError
        except OSError:
            editor = os.environ["EDITOR"]
            subprocess.call((editor, path))


def main():
    args = docopt.docopt(__doc__)
    config_dir = appdirs.user_data_dir("RSS-filter", "U2Ft")
    config, filters = check_config(config_dir)

    if not filters or args["--edit"]:
        if filters is None:
            print "No filters specified."
        elif isinstance(filters, tuple) and filters[0] is False:
            print "Filters file is invalid: {}\n".format(filters[1])

        filters_path = os.path.join(config_dir, "filters.json")
        print "Opening filters file (\"{}\")...".format(filters_path)
        open_file(filters_path)
        exit(4)

    reader = GoogleReader(config["client_ID"], config["client_secret"], config["refresh_token"])

    if args["--list"]:
        for f in reader.list_feeds():
            try:
                print f
            except UnicodeEncodeError:
                print f.encode("cp850", "backslashreplace")
        exit(0)

    feed_count, item_count = reader.apply_filters(filters)
    if feed_count == 1:
        if item_count == 1:
            print "\n1 matching item was found in 1 matching feed."
        else:
            print "\n{} matching items were found in 1 matching feed.".format(item_count)
    else:
        if item_count == 1:
            print "\n1 matching item was found in {} matching feeds.".format(feed_count)
        else:
            print "\n{} matching items were found in {} matching feeds.".format(item_count, feed_count)


if __name__ == "__main__":
    main()
