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

from lib import wphttp
from lib import wpprint
import re

class wpusers:
	check = wphttp.check()
	printf = wpprint.wpprint()
	def __init__(self,agent,proxy,redirect,url):
		self.url = url 
		self.req = wphttp.wphttp(agent=agent,proxy=proxy,redirect=redirect)
                self.usersFeed = []
                self.usersJson = []
                self.usersAuthor = []

        def wayjson(self):
                # Enumeration users via wp-json
                # https://www.exploit-db.com/exploits/41497/
                try:
                        url = self.check.checkurl(self.url,"/wp-json/wp/v2/users")
                        self.printf.ipri(" %s" %(url),color="g")
                        resp = self.req.send(url)
                        if resp.getcode() == 200:
                                html = resp.read()
                                user = json.loads(html,"utf-8")
                                for x in range(len(user)):
                                        self.usersJson.append(user[x]["name"])
                        # print self.usersJson
                except Exception,e:
                        pass

        def wayfeed(self):
                # Enumeration users via /?feed=rss2
                try:
                        url = self.check.checkurl(self.url,"/?feed=rss2")
                        self.printf.ipri(" %s" %(url),color="g")
                        resp = self.req.send(url)
                        if resp.getcode() == 200:
                                html = resp.read()
                                user = re.findall('<dc:creator><!\[CDATA\[(.+?)\]\]></dc:creator>',html)
                        if user:
                                self.usersFeed.extend(user)
                        # print self.usersFeed
                except Exception,e:
                        pass

        def wayauthor(self):
                # Enumeration users via /?author=
                for x in range(0,15):
                        try:
                                url = self.check.checkurl(self.url,"/?author="+str(x))
                                self.printf.ipri(" %s" %(url),color="g")
                                resp = self.req.send(url)
                                # print resp.getcode()
				if resp.getcode() == 200:
					html = resp.read()
                                        user = re.findall('author author-(.+?) ',html)
                                        user_= re.findall(r'/author/(\w+?)/',html)
                                        if user:
                                                self.usersAuthor.extend(user)
                                        if user_:
                                                self.usersAuthor.extend(user_)
                                        # print self.usersAuthor
                        except Exception,e:
                                # print 'in except'
                                pass


	def run(self):
		self.printf.test("Enumeration usernames...")

                self.wayjson()
                self.wayfeed()
                self.wayauthor()

		login_new = []

                self.printf.ipri(" names in [/wp-json/wp/v2/users,/?feed=rss2,/?author=x]:",color="g")
                for l in self.usersJson,self.usersFeed,self.usersAuthor:
                        self.printf.ipri("   %s" %(l),color="g")
                        for i in l: 
                                if i not in login_new:
                                        login_new.append(i)
		##################
		try:
			if login_new != []:
				for a in range(len(login_new)):
                                        u = login_new[a]
                                        if "%20" in u: 
						self.printf.ipri(" ID: %s   |  Login: %s"%(a,u.replace('%20',' ')),color="g")
					else:
						self.printf.ipri(" ID: %s  |  Login: %s"%(a,u),color="g")
				print ""
			if login_new == []:
				self.printf.ipri("Not found usernames",color="r")
		except Exception as error:
			self.printf.ipri("Not found usernames",color="r")
