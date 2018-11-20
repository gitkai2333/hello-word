#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import datetime
import hashlib
import hmac
import json
import time
import urllib
import urllib.parse
import urllib.request
import requests
import coincurve
from urllib import parse
from binascii import hexlify, unhexlify

# 此处填写APIKEY

ACCESS_KEY = "R8gHSqzBiSX"
SECRET_KEY = "dad44786f7adb2132cfedb76f3491b52421a0695d9d2387258c3c963c1334c67"



# API 请求地址
MARKET_URL = "http://47.96.116.164:6602"
TRADE_URL = "http://47.96.116.164:6602"

# 首次运行可通过get_accounts()获取acct_id,然后直接赋值,减少重复获取。
ACCOUNT_ID = None

#'Timestamp': '2017-06-02T06:13:49'

def http_request(url, params,method, add_to_headers=None):
    headers = {
        "Content-type": "application/json",
   }
    if add_to_headers:
        headers.update(add_to_headers)
 #   postdata = urllib.parse.urlencode(params)
    postdata = json.dumps(params)
  #  print(postdata)
 #   print(url)
    if method == 'POST':
        response = requests.post(url,data = postdata,headers= headers )
    else:
        response = requests.get(url) 
    try:
        
        if response.status_code == 200:
            print(response.json()) 
        else:
            print(response.text) 
    except BaseException as e:
        print("httpGet failed, detail is:%s,%s" %(response.text,e))
        return

def ecsign(rawhash, key):
    pk = coincurve.PrivateKey(key)
    signature = pk.sign_recoverable(rawhash, hasher=None)
    signature = base64.b64encode(signature)
    return signature

def hmacsha256(message):
    bmsg = str.encode(message)
    return hmac.new(key=b'', msg=bmsg, digestmod=hashlib.sha256).digest();


def api_key_req(method,params, request_path):
    timestamp = str(int(time.time()))
    
    params_to_sign = {
                      'SignatureMethod': 'HmacSHA256',
                      'SignatureVersion': '1',
                      'apiKey': ACCESS_KEY,
                      'Timestamp': timestamp}
    if method == 'GET':
          params_to_sign.update(params)                  
    host_url = TRADE_URL
    host_name = urllib.parse.urlparse(host_url).hostname
    params_sort = sorted(params_to_sign.items(), key=lambda d: d[0], reverse=False)
  #  print(params_sort)
   # host_name = host_name.lower()
    signature = createSign(params_sort, method, host_name, request_path, SECRET_KEY)
   # print(params_to_sign['Signature'])
   # print(params_to_sign)
    url = host_url + request_path + '?' + urllib.parse.urlencode(params_sort) + '&'+'Signature='+parse.quote(signature)

    return http_request(url, params,method)


def createSign(pParams, method, host_url, request_path, secret_key):  
    encode_params = urllib.parse.urlencode(pParams)
    payload = [method, host_url, request_path, encode_params]
    payload = '\n'.join(payload)
    hashed = hmacsha256(payload)
  #  print(hashed)

    signature = ecsign(hashed,unhexlify(secret_key))
    return signature

def order_req():
     method = 'POST'
     url = "/test1/R8gHSqzBiSX/orders/batch/create"

     params = {"ords":[
        {"side":"S","mkt":"ETC_ETH","price":"1","qty":"2"}]}

     api_key_req(method,params, url)

def query_trd():
     method = 'GET'
     url = "/test1/R8gHSqzBiSX/records/ordnum"
     params = {'ordNum':'2018111921899018240'}
     api_key_req(method,params, url)

def main():
    begin_time = time.time();
    count =0
#    while(time.time() - begin_time < 1):
    for i in range(12):
        query_trd()
        count +=1
    print(count)

if __name__ == '__main__':
    main()