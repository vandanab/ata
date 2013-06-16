#!/usr/bin/env python
'''
Created on Jun 14, 2013
@author: Vandana Bachani
ATA is a helper to access twitter REST api.
With the new twitter authentication model in place,
ATA can help you make twitter API calls easily.
One needs to create an instance of Main class for every new application.
It supports both app-user and app-only, authentication based requests
For app-user requests access tokens should be provided.
Needs oauth2 library: https://github.com/brosner/python-oauth2
'''
import base64
import cjson
import httplib2
import oauth2 as oauth
import time
import urllib

class Main():
  TWITTER_TOKEN_URI = "https://api.twitter.com/oauth2/token"
  TWITTER_INVALIDATE_TOKEN_URI = "https://api.twitter.com/oauth2/invalidate_token"
  
  def __init__(self, app_consumer_key, app_consumer_secret):
    self.app_consumer_key = app_consumer_key
    self.app_consumer_secret = app_consumer_secret
    self.request_map = {}
    self.request_map_app_only = {}
    self.bearer_token = None
  
  """This method makes an app-user authentication based Twitter REST API request.
  
  This mode of authentication is supported by most of the Twitter REST APIs.
  The public APIs which don't specifically need explicit user token for
  getting private data about a user, or posting to a user profile, etc.
  User rate limits apply.
  Params:
  base_url: the twitter api url one is trying to call.
    example: https://api.twitter.com/1.1/search/tweets.json
  params: url-encoded (% encoded) parameters to the api.
    example: q=%23freebandnames&result_type=mixed&count=4
  access_token: access_token for the user context, cannot be generated
    without directing user on a web interface to enter their credentials to get
    the access token.
    Purely for research usage.
    Can be extended to support oauth redirection capability later. 
  access_secret: access_secret for the user context.
  http_method: GET or POST
  post_body: None if method is GET
  http_headers: a dict of additional http headers to be added to the request.
  sleep_rate_limit_exhausted: whether to wait for the rate limit to reset
  """
  def request(self, base_url, params, access_token, access_secret,
              http_method="GET", post_body=None, http_headers=None,
              sleep_rate_limit_exhausted=True):
    if not self.check_limit_exceeded(base_url, sleep_rate_limit_exhausted):
      return None
    self.request_params = {"base_url": base_url, "params": params,
                           "http_method": http_method, "post_body": post_body,
                           "headers": http_headers}
    response = None
    try: 
      consumer = oauth.Consumer(key=self.app_consumer_key,
                                secret=self.app_consumer_secret)
      token = oauth.Token(key=access_token, secret=access_secret)
      client = oauth.Client(consumer, token)
      url = base_url + "?" + params
      response, content = client.request(url,
                                         method=http_method,
                                         body=post_body,
                                         headers=http_headers,
                                         force_auth_header=True)
      self.update_request_map(base_url, response)
      if response["status"] != "200":
        print response
        if response["status"] == "500":
          print "Bad request:", self.request_params
          print "access token and secret will not be shown..."
      else:
        #print content
        #print self.request_map
        return content
    except:
      print "An oauth request related exception occurred"
      if response:
        print "Response from server: ", response
        print "Something might be wrong with parsing the response..."
    return None

  """This method makes an app-only authentication based Twitter REST API request.
  
  This mode of authentication is supported by few Twitter REST APIs.
  The public APIs which don't specifically need explicit user token for
  getting private data about a user, or posting to a user profile, etc.
  App rate limits apply.
  Params:
  base_url: the twitter api url one is trying to call.
    example: https://api.twitter.com/1.1/search/tweets.json
  params: url-encoded (% encoded) parameters to the api.
    example: q=%23freebandnames&result_type=mixed&count=4
  post_body: None if method is GET
  http_headers: a dict of additional http headers to be added to the request.
  sleep_rate_limit_exhausted: whether to wait for the rate limit to reset
  """
  def request_apponly(self, base_url, params,
                      http_method="GET", post_body=None, http_headers=None,
                      sleep_rate_limit_exhausted=True):
    if not self.check_limit_exceeded(base_url, sleep_rate_limit_exhausted, True):
      return None
    self.request_params = {"base_url": base_url, "params": params,
                           "http_method": http_method, "post_body": post_body,
                           "headers": http_headers}
    http = httplib2.Http()
    while True:
      if not self.bearer_token:
        self.bearer_token = self.get_bearer_token()
      url = base_url + "?" + params
      if not http_headers:
        http_headers = {}
      http_headers["Authorization"] = "Bearer " + self.bearer_token
      response = None
      try:
        response, content = http.request(url,
                                         http_method,
                                         post_body,
                                         http_headers)
        self.update_request_map(base_url, response, True)
        if response["status"] != "200":
          print response
          content = cjson.decode(content)
          if "errors" in content:
            for i in content["errors"]:
              print str(i["code"]), ": ", i["message"]
              if i["code"] == 89:
                self.bearer_token = None
                continue
          if response["status"] == "500":
            print "Bad request:", self.request_params
          break
        else:
          #print content
          #print self.request_map_app_only
          return content
      except:
        print "An app-auth request related exception occurred"
        if response:
          print "Response from server: ", response
          print "Something might be wrong with parsing the response..."
      return None
  
  def check_limit_exceeded(self, base_url, sleep_if_limit_exceeded, 
                           app_only=False):
    request_map = self.request_map
    if app_only:
      request_map = self.request_map_app_only
    if base_url in request_map:
      if request_map[base_url]["remaining_limit"] == 0:
        time_to_reset = request_map[base_url]["reset_time"] - time.time() 
        if time_to_reset > 0:
          if sleep_if_limit_exceeded:
            print "I need to sleep for % secs as rate limit is exhausted..." % \
              time_to_reset
            time.sleep(time_to_reset+2) #sleep for rate-limit-reset time + 2 secs
          else:
            print "rate limit exhausted, try later..."
            return False
    return True
  
  def update_request_map(self, base_url, response_hdr, app_only=False):
    request_map = self.request_map
    if app_only:
      request_map = self.request_map_app_only
    if "x-rate-limit-reset" in response_hdr and \
      "x-rate-limit-remaining" in response_hdr:
      reset_time = float(response_hdr["x-rate-limit-reset"])
      limit = float(response_hdr["x-rate-limit-remaining"])
      if base_url in request_map:
        if request_map[base_url]["reset_time"] < reset_time:
          request_map[base_url]["reset_time"] = reset_time
      else:
        request_map[base_url] = {"reset_time": reset_time}
      request_map[base_url]["remaining_limit"] = limit

  def get_bearer_token(self):
    http = httplib2.Http()
    encoded_consumer_details = self.encode_key_secret()
    headers = {"Authorization": "Basic " + encoded_consumer_details,
               "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"
               }
    body = "grant_type=client_credentials"
    response, content = http.request(Main.TWITTER_TOKEN_URI,
                 "POST",
                 body,
                 headers)
    if response["status"] == "200":
      content = cjson.decode(content)
      #print content
      assert content["token_type"] == "bearer"
      return content["access_token"]
    print "Error occurred while fetching the bearer token..."
    return None

  def invalidate_bearer_token(self):
    if not self.bearer_token:
      print "Bearer Token is not valid."
      return
    http = httplib2.Http()
    encoded_consumer_details = self.encode_key_secret()
    headers = {"Authorization": "Basic " + encoded_consumer_details,
               "Content-Type": "application/x-www-form-urlencoded"
               }
    body = "access_token=" + self.bearer_token
    response, content = http.request(Main.TWITTER_INVALIDATE_TOKEN_URI,
                 "POST",
                 body,
                 headers)
    if response["status"] == "200":
      print "token invalidated..."
    elif response["status"] == "403":
      content = cjson.decode(content)
      print content["message"]

  def encode_key_secret(self):
    encoded_key = urllib.quote_plus(self.app_consumer_key)
    encoded_secret = urllib.quote_plus(self.app_consumer_secret)
    credentials = encoded_key + ":" + encoded_secret
    encoded_credentials = base64.b64encode(credentials)
    return encoded_credentials


if __name__ == "__main__":
  """
  This is just an example for testing the class and hence is commented out.
  (The key and secret strings are from twitter api page and you need to work
  with your own keys).
  """
  """
  CONSUMER_KEY = "xvz1evFS4wEEPTGEFPHBog"
  CONSUMER_SECRET = "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg"
  access_rest_api = Main(CONSUMER_KEY, CONSUMER_SECRET)
  for i in range(182):
    content = access_rest_api.request(
    'https://api.twitter.com/1.1/search/tweets.json', 'q=chocolate',
    '370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb',
    'adfadsflkthpoiy4230847VR71aS3tuAkyuezGg5JA',
    sleep_rate_limit_exhausted=False)
  content = access_rest_api.request_apponly(
    'https://api.twitter.com/1.1/users/lookup.json',
    'screen_name=twitterapi,twitter')
  """
  pass
