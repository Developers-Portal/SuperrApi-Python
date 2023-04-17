# -*- coding: utf-8 -*-
"""
Created on Wed Mar  8 11:41:10 2023

@author: Yatish
"""

from superapi import superApi 


c1 = superApi( api_key= "Your Api key" , userId= "Your trading ID", password= "Password",apisecret= "Your secret key")

c1.generateSession()


# order = c1.placeOrder()

# print (order)
