import logging
import requests
import os
import json
import sys
import urllib3
import azure.functions as func
import pyodbc


def write_http_response(status, body_text):
    return_dict = {
        "status": status,
        "body": body_text
    }
    output = open(os.environ['res'], 'w')
    output.write(json.dumps(return_dict))

def log(text):
    print(text)
    logging.info(text)

def bot_answer(channel, answer):
    log("Attempting to answer")
    pl = {"text": answer,
          "channel": channel}

    urllib3.disable_warnings()
    http = urllib3.PoolManager()
    encoded_data = json.dumps(pl).encode('utf-8')
    bot_token = "Bearer xoxb-412513733287-410767734736-ZfhPRtgcnAamxVOBm2HbHEfm"
    
    r = http.request(
      'POST',
      'https://slack.com/api/chat.postMessage',
      body = encoded_data,
      headers={'Content-Type': 'application/json', 'Authorization' : bot_token })
    
    log(r.status)
    log(r._body)
    return(r)

def main(req: func.HttpRequest) -> func.HttpResponse:
    
    log('YoStroop was triggered.')

    req_body = req.get_json()
    challenge = req_body.get('challenge')
    event = req_body.get('event')
    name = req_body.get('name')

    if challenge:
        return func.HttpResponse (f"{challenge}", status_code = 200)
    elif event:
        user = event.get('user')
        message = event.get('text')
        log(f"Received {message}")
        channel = event.get('channel')
        if (user is not None) and (message.find(":stroopwafel:") >= 0):
            r = bot_answer(channel, f"user {user} said something about stroopwafels - check it out!")
            return func.HttpResponse (r._body, status_code = r.status)
        else   
            return func.HttpResponse ("", status_code = 0)
    elif name:
        return func.HttpResponse (f"{name}", status_code = 200)
    else:
        return func.HttpResponse (f"Oh crap", status_code = 400)