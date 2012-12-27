#!/usr/bin/env python2


import os
import errno
import stat
from cStringIO import StringIO

import libgreader
import requests
import configobj
import validate
import appdirs


def short_link(URL):
    """Create an is.gd short link for the specified URL. Returns the original URL on failure."""
    params = {"format": "json", "url": URL, "logstats": 0}
    r = requests.get("http://is.gd/create.php", params=params)
    if r.ok:
        short_link = r.json["shorturl"]
    else:
        short_link = URL
    return short_link


class GoogleReader:
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
        auth_URL = short_link(auth.buildAuthUrl())

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
        return config
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


def main():
    config_dir = appdirs.user_data_dir("RSS-filter", "U2Ft")
    config = check_config(config_dir)

    reader = GoogleReader(config["client_ID"], config["client_secret"], config["refresh_token"])

    print reader.user_info()


if __name__ == "__main__":
    main()
