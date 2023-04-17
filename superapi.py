# -*- coding: utf-8 -*-
"""
Created on Sat Mar  4 11:42:42 2023

@author: Yatish
"""

from cryptography.hazmat.primitives import hashes, hmac
import json 
import requests
import hmac
import hashlib
import base64
import time


class superApi():
    
    _rootUrl = "https://openapi.stoxkart.com"
   
    
    url = {"auth.login" : "/auth/login",
           "auth.2fa" : "/auth/twofa/verify",
           "auth.generate.session" : "/auth/token"
        }
    
    errMessage = {
        "auth.login" : "Please check your apiKey, userId, passowrd or apiSecret.",
        "auth.login.enable.2fa" : "Please enable TOTP with Administrator.",
        "auth.2fa" : "Invalid TOTP",
        "auth.generate.session" : "Invalid input, PLease try again."
        }
    
    def __init__(self, api_key=None, userId=None, password=None, apisecret = None):
        self.api_key = api_key
        self.apisecret = apisecret
        self.userId = userId
        self.password = password
        self._getRequestToken()
       
    def _generate_url(self, urlKey, queryParam=False):
        if queryParam:
            return "{}{}?api-key={}".format(self._rootUrl, self.url[urlKey], self.api_key)
        else:
            return "{}{}".format(self.url[urlKey])
           
    
    def _request(self, url_key, data, headers, queryParam=False):
         url = self._generate_url(url_key, queryParam)
         print("### ", url, data, headers, queryParam)
         try:
             r = requests.post(url, data, headers)
         except Exception as e:
             raise e
         return r
    
    def _checkResponse(self, url_key, response): 
        print("##### ", url_key, response)
        if response.status_code != 200:
            #print(self.errMessage["auth.login"])
            print("Response: {code} {content}".format(code=response.status_code, content=response.content.upper()))
            raise Exception(response.content)
        
        if response.status_code == 200:
            data = json.loads(response.content.decode("utf8"))
            print(url_key.upper(), " : " , data)
            if url_key == "auth.login" and data["data"]["is_2fa_enabled"]:
                print(self.errMessage["auth.login.enable.2fa"])
            return data
        
    def _getRequestToken(self):
        params = {
            "platform": "api",
            "data": {
                "client_id": self.userId,
                "password": self.password
            }
        }
        
        resp = self._request("auth.login", json.dumps(params), self.getCommonHeader(), True)
        data = self._checkResponse("auth.login", resp)

        self.requestToken = data["data"]["request_token"]
        totp = input('Enter TOPT to validate login : ')
        self.validate_2fa(totp)
        
            
    def validate_2fa(self, totp):
        params = {
            "platform": "api",
            "data": {
            "client_id":  self.userId,
            "req_token": self.requestToken,
            "action": "api-key-validation",
            "otp": totp
            }
        }     
        
        resp = self._request("auth.2fa", json.dumps(params), self.getCommonHeader(), True)
        data = self._checkResponse("auth.2fa", resp)

        self.requestToken = data["data"]["request_token"]
   
    def getSignature(self):
        key1 = bytes(self.api_key +  self.requestToken , 'UTF-8')
        key2 = bytes(self.apisecret, 'UTF-8')        
        self.signature = hmac.new(key1, key2, hashlib.sha256).hexdigest()
     
    def generateSession(self):
        self.getSignature()
                    
        params = {
            "api_key": self.api_key,
            "signature": self.signature,
            "req_token": self.validatedtoken
        }
        
        print(params)
        resp = self._request("auth.generate.session", json.dumps(params), self.getCommonHeader())
        data = self._checkResponse("auth.generate.session", resp)
        self.accessToken = data["data"]["request_token"]
     
    def getCommonHeader(self):
        
        return {"Content-Type": "application/json"}
 
    # def combine_apikey_reqtoken(apikey,request_token):
        
    #     sessionid = (apikey + ":"+ request_token)
           
    #     return sessionid

    # sessionid = combine_apikey_reqtoken("1gHvz2hpELN4CtZ7","624ece9aa0a9743130f8200bf8405020a52c5b89e9fe33191a5eb33ae61bf8e8")

 
    
    def getHeaders(self):
        return {"Content-Type": "application/json",
                 "Accept-Type" : "application/json",
                 "request_token" : self.requestToken,
                 # "x-session" : "{}:{}".format(self.api_key, self.accessToken),
                 "x-Platform" : "api",
                 "X-Access-Token" : self.accessToken,
                 "x-Api-key": self.api_key}	
     
    
    """Convert positions"""
    
    def convertPosition(self,action,
                    exchange,
                    token,
                    order_type,
                    product_type,
                    quantity,
                    new_product_type):
                        
                  params ={
                    "action": action,
                    "exchange": exchange,
                    "token": token,
                    "product_type":product_type,
                    "quantity": quantity,
                      "new_product_type": new_product_type
                    }
                  url = "{}{}".format(self._rootUrl, "/order/v1/position-conversion" )
                  resp = requests.post(url ,data=json.dumps(params), headers = self.getHeaders())
                  print(resp)
    
    """ Get fund details"""
    
    def getFundDetails(self):
        url = "{}{}".format(self._rootUrl, "/fund/v1/fund-details" )
        params = None
        resp = requests.get(url ,data=json.dumps(params), headers = self.getHeaders())
        print(resp)
        
        
    """ Get Positions"""    
    def getPositions(self):
        url = "{}{}".format(self._rootUrl, "/portfolio/v1/position" )
        params = None
        resp = requests.get(url ,data=json.dumps(params), headers = self.getHeaders())
        print(resp)
        
    """ Get holding"""   
        
    def getHolding(self):
        url = "{}{}".format(self._rootUrl, "/portfolio/v1/holding" )
        params = None
        resp = requests.get(url ,data=json.dumps(params), headers = self.getHeaders())
        print(resp)
     
    """ Get order book"""    
        
    def getOrderbook(self):
        url = "{}{}".format(self._rootUrl, "report/v1/order-book" )
        params = None
        resp = requests.get(url ,data=json.dumps(params), headers = self.getHeaders())
        print(resp)    
    
    """ Get TradeBook"""
    
    def getTradebook(self):
        url = "{}{}".format(self._rootUrl, "report/v1/getTradeBook" )
        params = None
        resp = requests.get(url ,data=json.dumps(params), headers = self.getHeaders())
        print(resp)    
        
             

    """"place order normal """

    def placeOrder(self
                    ,action
                    ,exchange,
                    token,
                    order_type,
                    product_type
                    ,quantity,
                    disclose_quantity,
                    price,
                    trigger_price,
                    square_off,
                    stop_loss,
                    trailing_stop_loss,
                    validity,
                    validity_date,
                    tag):
        
        params = {
        "action": action,
        "exchange": exchange,
        "token": token,
        "order_type": order_type,
        "product_type": product_type,
        "quantity": quantity,
        "disclose_quantity": disclose_quantity,
        "price": price,
        "trigger_price": trigger_price,
        "square_off": square_off,
        "stop_loss": stop_loss,
        "trailing_stop_loss": trailing_stop_loss,
        "validity": validity,
        "validity_date": validity_date,
        "tag": tag}
      
        url = "{}{}".format(self._rootUrl, "/orders/normal" )
        resp = requests.post(url ,data=json.dumps(params), headers = self.getHeaders())
        print (resp.content)
        return resp
        # resp = requests.post(url,d ata=json.dumps(params), headers = headers )

      
        """Modify normal order"""
        
        def ModifyOrder(self,
                    exchange,
                    token,
                    order_type,
                    quantity,
                    disclose_quantity,
                    price,
                    trigger_price,
                    validity,
                    order_id):
         
              params ={
            "exchange"    : exchange,
            "token"       : token,
            "order_type"  : order_type,
            "quantity"    : quantity,
            "disclose_quantity": disclose_quantity,
            "price"       : price,
            "trigger_price":trigger_price,
            "validity"    : validity,
            "order_id"    : order_id
        }
           
              url = "{}{}".format(self._rootUrl, "/orders/normal" )
              resp = requests.post(url ,data=json.dumps(params), headers = self.getHeaders())
              print (resp.content)
              return resp
          # resp = requests.post(url,d ata=json.dumps(params), headers = headers )

        """Cancel normal order"""
         
        def cancelorder(self,
                          order_id):
              
                    params ={
                  "variety"     : variety,
                  "order_id"    : order_id
              }
                
                    url = "{}{}".format(self._rootUrl, "/orders/normal" )
                    resp = requests.post(url ,data=json.dumps(params), headers = self.getHeaders())
                    print(resp)


 
 
        """"place order AMO """
        
        def placeOrder_amo(self
                        ,action
                        ,exchange,
                        token,
                        order_type,
                        product_type
                        ,quantity,
                        disclose_quantity,
                        price,
                        trigger_price,
                        square_off,
                        stop_loss,
                        trailing_stop_loss,
                        validity,
                        validity_date,
                        tag):
            
            params = {
            "action": action,
            "exchange": exchange,
            "token": token,
            "order_type": order_type,
            "product_type": product_type,
            "quantity": quantity,
            "disclose_quantity": disclose_quantity,
            "price": price,
            "trigger_price": trigger_price,
            "square_off": square_off,
            "stop_loss": stop_loss,
            "trailing_stop_loss": trailing_stop_loss,
            "validity": validity,
            "validity_date": validity_date,
            "tag": tag}
          
            url = "{}{}".format(self._rootUrl, "/orders/amo" )
            resp = requests.post(url ,data=json.dumps(params), headers = self.getHeaders())
            print (resp.content)
            return resp
            # resp = requests.post(url,d ata=json.dumps(params), headers = headers )
        
          
            """Modify amo order"""
            
            def ModifyOrder_amo(self,
                        exchange,
                        token,
                        order_type,
                        quantity,
                        disclose_quantity,
                        price,
                        trigger_price,
                        validity,
                        order_id):
             
                  params ={
                "exchange"    : exchange,
                "token"       : token,
                "order_type"  : order_type,
                "quantity"    : quantity,
                "disclose_quantity": disclose_quantity,
                "price"       : price,
                "trigger_price":trigger_price,
                "validity"    : validity,
                "order_id"    : order_id
            }
               
                  url = "{}{}".format(self._rootUrl, "/orders/amo" )
                  resp = requests.post(url ,data=json.dumps(params), headers = self.getHeaders())
                  print (resp.content)
                  return resp
              # resp = requests.post(url,d ata=json.dumps(params), headers = headers )
        
            """Cancel amo order"""
             
            def cancelorder_amo(self,
                              order_id):
                  
                        params ={
                      "variety"     : variety,
                      "order_id"    : order_id
                  }
                    
                        url = "{}{}".format(self._rootUrl, "/orders/amo" )
                        resp = requests.post(url ,data=json.dumps(params), headers = self.getHeaders())
                        print(resp)
        
        
        
        
        """"place order BO """
        
        def placeOrder_bo(self
                        ,action
                        ,exchange,
                        token,
                        order_type,
                        product_type
                        ,quantity,
                        disclose_quantity,
                        price,
                        trigger_price,
                        square_off,
                        stop_loss,
                        trailing_stop_loss,
                        validity,
                        validity_date,
                        tag):
            
            params = {
            "action": action,
            "exchange": exchange,
            "token": token,
            "order_type": order_type,
            "product_type": product_type,
            "quantity": quantity,
            "disclose_quantity": disclose_quantity,
            "price": price,
            "trigger_price": trigger_price,
            "square_off": square_off,
            "stop_loss": stop_loss,
            "trailing_stop_loss": trailing_stop_loss,
            "validity": validity,
            "validity_date": validity_date,
            "tag": tag}
          
            url = "{}{}".format(self._rootUrl, "/orders/bo" )
            resp = requests.post(url ,data=json.dumps(params), headers = self.getHeaders())
            print (resp.content)
            return resp
            # resp = requests.post(url,d ata=json.dumps(params), headers = headers )
        
          
            """Modify amo order"""
            
            def ModifyOrder_bo(self,
                        exchange,
                        token,
                        order_type,
                        quantity,
                        disclose_quantity,
                        price,
                        trigger_price,
                        validity,
                        order_id):
             
                  params ={
                "exchange"    : exchange,
                "token"       : token,
                "order_type"  : order_type,
                "quantity"    : quantity,
                "disclose_quantity": disclose_quantity,
                "price"       : price,
                "trigger_price":trigger_price,
                "validity"    : validity,
                "order_id"    : order_id
            }
               
                  url = "{}{}".format(self._rootUrl, "/orders/bo" )
                  resp = requests.post(url ,data=json.dumps(params), headers = self.getHeaders())
                  print (resp.content)
                  return resp
              # resp = requests.post(url,d ata=json.dumps(params), headers = headers )
        
            """Cancel normal order"""
             
            def cancelorder_bo(self,
                              order_id):
                  
                        params ={
                     
                      "order_id"    : order_id
                  }
                    
                        url = "{}{}".format(self._rootUrl, "/orders/bo" )
                        resp = requests.post(url ,data=json.dumps(params), headers = self.getHeaders())
                        print(resp)
        
          






    
