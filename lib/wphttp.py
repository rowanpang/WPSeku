#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# WPSeku: Wordpress Security Scanner
#
# @url: https://github.com/m4ll0k/WPSeku
# @author: Momo Outaadi (M4ll0k)
#
# WPSeku is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation version 3 of the License.
#
# WPSeku is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with WPSeku; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

import requests


class wphttp(object):
    def __init__(self, **kwargs):
        self.agent = kwargs.get('agent', None)
        self.proxy = kwargs.get('proxy', None)
        self.redirect = kwargs.get('redirect', None)

    def send(self, url, method='GET', payload=None, headers=None, cookies=None):
        payload = payload or dict()
        headers = headers or dict()
        cookies = cookies or dict()
        proxies = dict()
        if self.proxy:
            proxies = dict(http=self.proxy, https=self.proxy)
        headers['User-agent'] = self.agent
        resp = requests.request(
            method=method,
            url=url,
            allow_redirects=self.redirect,
            data=payload,
            headers=headers,
            cookies=cookies,
            proxies=proxies
        )
        return resp


class check:
    def checkurl(self, url, path):
        if url.endswith('/') and path.startswith('/'):
            return url[:-1] + path
        elif not url.endswith('/') and not path.startswith('/'):
            return url + "/" + path
        else:
            return url + path

    def checkpayload(self, url, payload):
        if url.endswith('/') and payload.startswith('/'):
            return url[:-1] + "?" + payload[1:]
        elif url.endswith('/'):
            return url[:-1] + "?" + payload
        else:
            return url + "?" + payload
