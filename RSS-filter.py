#!/usr/bin/env python2

import libgreader
import requests


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
        else:
            self.refresh_token = self._get_refresh_token()

        self.auth = self._authenticate()
        self.libgreader = libgreader.GoogleReader(self.auth)

    def _authenticate(self):
        payload = {"client_id": self.client_ID, "client_secret": self.client_secret,
                   "refresh_token": self.refresh_token, "grant_type": "refresh_token"}
        r = requests.post("https://accounts.google.com/o/oauth2/token", data=payload)
        access_token = r.json["access_token"]

        auth = libgreader.OAuth2Method(self.client_ID, self.client_secret)
        auth.setRedirectUri("urn:ietf:wg:oauth:2.0:oob")
        auth.access_token = access_token

        return auth

    def _get_refresh_token(self):
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


def main():
    client_ID = raw_input("Google OAuth Client ID\n:  ")
    client_secret = raw_input("Google OAuth Client Secret\n:  ")
    reader = GoogleReader(client_ID, client_secret, None)

    print reader.user_info()


if __name__ == "__main__":
    main()
