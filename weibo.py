#coding:utf-8


import time
import urllib
import urllib2
import httplib
import json
import urlparse

import base64
import hashlib




class Cache(object):
    def __init__(self, default_expires= 60*60*24-1):
        self.default_expires = default_expires # 默认失效时间, 默认4个小时
        self._data = {}
        
    def _get(self, key):
        return self._data.get(key)
    
    def _set(self, key, item):
        self._data[key] = item
        
    def _remove(self, key):
        self._data.pop(key)
            
    
    def set(self, key, value, expires=None):
        if expires is None:
            expires = self.default_expires
        self._set(key, {'expires': time.time()+expires, 'value': value})
        
    def get(self, key):
        item = self._get(key)
        if item:
            if not self.is_expired(item):
                return item['value']
            else:
                self._remove(key) #过期就删了
    
    def is_expired(self, item):
        if item['expires'] > time.time():
            return False
        return True

def _request(method, url, data=None, handlers=None, addheaders=None):
    handlers = handlers or []
    handlers.append(urllib2.ProxyHandler({'https': 'web-proxy.oa.com:8080'}))
    opener = urllib2.build_opener(*handlers)
    if addheaders:
        opener.addheaders += addheaders
    if data:
        data = urllib.urlencode(data) if isinstance(data, dict) else urllib2.quote(data)
    if method == 'GET':
        if data:
            url = url + '?' + data
        data = None
    return opener.open(url, data)

class WeiboOauth(object):
    APP_KEY = ''
    APP_SECRET = ''
    REDIRECT_URI = ''

    def __init__(self, username, password):
        self.username = username
        self.password = password

    def _encry_password(self, servertime, nonce):
        pwd = hashlib.sha1(self.password).hexdigest()
        pwd1 = hashlib.sha1(pwd).hexdigest()
        pwd2 = pwd1 + str(servertime) + str(nonce)
        pwd3 = hashlib.sha1(pwd2).hexdigest()
        return pwd3

    def _encry_user(self):
        username = urllib.quote(self.username)
        username = base64.encodestring(username)[:-1]
        return username

    def _prelogin(self):
        callback = 'sinaSSOController.preloginCallBack'
        url = 'https://login.sina.com.cn/sso/prelogin.php'
        params = {
            'entry': 'openapi',
            'callback': callback,
            'su': self._encry_user(),
            'client': 'ssologin.js(v.13.22)',
            '_': js_now()
        }
        u = _request('GET', url, params)
        data = u.read()
        data = data[len(callback) + 1: -1]
        return json.loads(data)

    def _login(self, prelogin_data):
        callback = 'sinaSSOController.loginCallBack'
        url = 'https://login.sina.com.cn/sso/login.php'
        params = {
            '_': js_now(),
            'callback': callback,
            'cdult': 2,
            'client': 'ssologin.js(v1.3.22)',
            'ct': 1800,
            'domain': 'weibo.com',
            'door': '',
            'encoding': 'UTF-8',
            'entry': 'openapi',
            'from': '',
            'gateway': 1,
            'nonce': prelogin_data['nonce'],
            'prelt': 102,
            'pwencode': 'wsse',
            'returntype': 'TEXT',
            's': 1,
            'savestate': 0,
            'servertime': prelogin_data['servertime'],
            'service': 'miniblog',
            'sp': self._encry_password(prelogin_data['servertime'], prelogin_data['nonce']),
            'su': self._encry_user(),
            'useticket': 1,
            'vsnd': 1,
            'vsnval': ''
        }
        u = _request('GET', url, params)
        data = u.read()[len(callback)+1: -2]
        return json.loads(data)

    def _authorize(self, login_data):
        url = 'https://api.weibo.com/oauth2/authorize'
        params = {
            'action': 'submit',
            'client_id': self.APP_KEY,
            'from': '',
            'isLoginSina': '',
            'passwd': '',
            'redirect_uri': self.REDIRECT_URI,
            'regCallback': '',
            'response_type': 'code',
            'state': '',
            'ticket': login_data['ticket'],
            'userId': self.username,
            'withOfficalFlag': 0,
        }
        class HTTPDontRedirect(urllib2.HTTPRedirectHandler):
            def http_error_302(self, req, fp, code, msg, headers):
                return urllib2.addinfourl(fp, headers, req.get_full_url(), code)
        referer = url + '?' + urllib.urlencode({
            'client_id': self.APP_KEY,
            'redirect_uri': self.REDIRECT_URI,
            'response_type': 'code',
        })

        opener = urllib2.build_opener(HTTPDontRedirect)
        u = _request('POST', url, params,
                          handlers=[HTTPDontRedirect],
                          addheaders=[('Referer', referer)]
                          )
        if u.getcode() == 302:
            redirect_uri = u.headers['location']
            query = urlparse.urlsplit(redirect_uri).query
            code = urlparse.parse_qs(query)['code'][0]
            return code
        else:
            raise Exception, u
            
    def _access_token_by_authorization_code(self, code):
        url = 'https://api.weibo.com/oauth2/access_token'
        params = {
            'client_id': self.APP_KEY,
            'client_secret': self.APP_SECRET,
            'redirect_uri': self.REDIRECT_URI,
            'code': code,
            'grant_type': 'authorization_code',
        }
        u = _request('POST', url, params)
        return json.loads(u.read())

    def authorize(self):
        data = self._prelogin()
        print data
        print
        data = self._login(data)
        print data
        print
        data = self._authorize(data)
        print data
        print
        return self._access_token_by_authorization_code(data)
    

def js_now():
    return int(time.time()*1000)

class WeiboAPIError(Exception):
    def __init__(self, info):
        self.info = info
        data = json.loads(info)
        self.error_code = data.get('error_code')
        self.request = data.get('request')
        self.error = data.get('error')

    def __str__(self):
        return '[%s in %s] %s'%(self.error_code, self.request, self.error)


class WeiboClient(object):
    cache = Cache()
    def __init__(self, username, password, host='https://api.weibo.com/2/'):
        self.username = username
        self.password = password
        self.host = host

    def login(self):
        data = self.cache.get(self.username)
        if not data:
            data = WeiboOauth(self.username, self.password).authorize()
            self.cache.set(self.username, data , expires=data['expires_in'])
        self.token = data['access_token']
        self.expires_in = data['expires_in']
        self.uid = data['uid']

    def request(self, method, path, data=None):
        url = self.host.rstrip('/') + '/' + path.lstrip('/')
        addheaders = [('Authorization', 'OAuth2 %s'%self.token)]
        try:
            u = _request(method, url, data, addheaders=addheaders)
            return json.loads(u.read())
        except urllib2.HTTPError, e:
            raise WeiboAPIError(e.read())
        

    def get(self, path, params=None):
        return self.request('GET', path, params)

    def post(self, path, params=None):
        return self.request('POST', path, params)


