import logging
import requests
import os
import json
import sys
import urllib3
import azure.functions as func
import pydocumentdb
import pydocumentdb.document_client as document_client
import re
from datetime import datetime


def post_to_slack_channel (auth_token, message, channel):
    """
    Post message `message` to Slack channel `channel`.
    """

    answer_payload = {"text": message, "channel": channel}

    urllib3.disable_warnings()
    http = urllib3.PoolManager()
    encoded_data = json.dumps(answer_payload).encode('utf-8')
    bot_token = f"Bearer {auth_token}"
    
    r = http.request(
      'POST',
      'https://slack.com/api/chat.postMessage',
      body = encoded_data,
      headers={'Content-Type': 'application/json', 'Authorization' : bot_token }
    )
    
    return(r)

def get_username_from_userid (auth_token, userid):
    """
    Uses the Slack API to convert the User IDs to user names.
    Returns a string containing the displayname for the given Slack User ID
    """

    urllib3.disable_warnings()
    http = urllib3.PoolManager()
    r = http.request(
        'GET',
        'https://slack.com/api/users.profile.get',
        {'token':auth_token, 'user':userid}
    )

    if r.status == 200:
        body = json.loads(r._body)
        profile = body.get("profile")
        if profile:
            name = profile.get("display_name")
        else:
            name = None
        return name
    else:
        return None

def get_cosmosdb_connection() -> document_client.DocumentClient:
    host = os.environ["YOSTROOP_DB_HOST"]
    key = os.environ["YOSTROOP_DB_KEY"]
    client = document_client.DocumentClient(host, {"masterKey" : key})

    db = os.environ["YOSTROOP_DB_NAME"]
    coll = os.environ["YOSTROOP_COLL_NAME"]
    coll_string = f"dbs/{db}/colls/{coll}"

    return client, coll_string

def send_document_cosmosdb(payload):
    """
    Uploads JSON document `payload` to Yostroop's COSMOS DB
    """
    client, coll_string = get_cosmosdb_connection()
    client.CreateDocument(coll_string, payload)

def log_gift(sender, receiver):
    """ 
    Creates and uploads a document of type gift to Yostroop's Cosmos DB
    """

    gift = { 
             "type":"gift",
             "timestamp": str(datetime.utcnow()),
             "sender": sender,
             "receiver": receiver 
            }

    send_document_cosmosdb(gift)
  
def debug_log_event (event):
    """
    Uploads a document of type `event` to Yostroop's Cosmos DB
    """
    data = { 
             "type":"event",
             "event": event,
             "timestamp": str(datetime.utcnow())
            }
    send_document_cosmosdb(data)

def debug_log_error (err):
    """
    Uploads a document of type `event` to Yostroop's Cosmos DB
    """
    data = { 
             "type":"error",
             "event": str(err),
             "timestamp": str(datetime.utcnow())
            }
    send_document_cosmosdb(data)

def install_client(data):
    logging.warning("Installing new client:")
    logging.warning(data)
    send_document_cosmosdb(data)

def list_gift_recipients(auth_token, gift_message):
    """
    Lists the receivers of the message containing a gift
    
    If the message is something like "<@x> <@y> :gift:", 
    this will return a list containing x and y's display names

    The message comes from Slack with user ids that have to 
    be converted to display names (for now - later, we can use IDs)
    """

    recipient_ids = re.findall("<@(.*?)>", gift_message)
    return [get_username_from_userid(auth_token, uid) for uid in recipient_ids]

def handle_slack_event(auth_token, event) -> func.HttpResponse:
    """
    Handles an object of the `event` type from Slack.
    For now, assumes all events are of type `message`. 

    It's triggered for all messages in a channel this bot is in.
    If the message contains a :stroopwafel: gift, we'll log it 
    to the database.
    """

    sender_id = event.get('user')
    message = event.get('text')
    channel = event.get('channel')

    logging.info(f"Debug level = {os.environ['YOSTROOP_DEBUG_LEVEL']}")

    if os.environ['YOSTROOP_DEBUG_LEVEL'] == "1":
        debug_log_event(event)

    if (sender_id is not None) and (message.find(":stroopwafel:") >= 0):
        
        recipient_names = list_gift_recipients(auth_token, message)
        sender = get_username_from_userid (auth_token, sender_id)

        recipient_count = 0
        # Save the gifts to the database:
        for recipient in recipient_names:
            if recipient:
                log_gift(sender, recipient)
                recipient_count = recipient_count + 1

        if recipient_count <= 0:
            return func.HttpResponse ("OK", status_code = 200)    
        elif recipient_count == 1:
            r = post_to_slack_channel (auth_token, f"user {sender} gave away a stroopwafel.", channel)
        else:
            r = post_to_slack_channel (auth_token, f"user {sender} gave away {recipient_count} stroopwafels.", channel)
        return func.HttpResponse (r._body, status_code = r.status)
    else:
        return func.HttpResponse ("OK", status_code = 200)

def handle_bad_request(req) -> func.HttpResponse:
    """
    Helper function to provide error messages and logging in case of a bad request
    """
    if os.environ['YOSTROOP_DEBUG_LEVEL'] == "1":
        debug_log_error(req)
    logging.warning("Bad request received: will handle by returning 400 Bad Request")
    return func.HttpResponse("Bad Request: I don't know how to handle that request.", status_code = 400)

def handle_oauth(code):
    urllib3.disable_warnings()
    http = urllib3.PoolManager()
    logging.warning(f"Using client: {os.environ['YOSTROOP_OAUTH_CLIENT']}")
    logging.warning(f"Using secret: {os.environ['YOSTROOP_OAUTH_SECRET']}")
    r = http.request(
        'POST',
        'https://slack.com/api/oauth.access',
        {
            "client_id": os.environ["YOSTROOP_OAUTH_CLIENT"],
            "client_secret": os.environ["YOSTROOP_OAUTH_SECRET"],
            "code": code
        }
    )

    if r.status == 200:
        body = json.loads(r._body)
        install_client(body)
        return func.HttpResponse (f"Installed new client", status_code = 200)
    else:
        logging.error("Error in OAUTH")
        logging.error(r)
        return handle_bad_request(r)


def get_team_key(team):

    client, coll_string = get_cosmosdb_connection()

    q = f"SELECT c.access_token FROM c WHERE c.team_id = '{team}'"
    query = { 'query': q }    

    options = {} 
    options['enableCrossPartitionQuery'] = True
    options['maxItemCount'] = 1

    result_iterable = client.QueryDocuments(coll_string, query, options)
    results = list(result_iterable)

    if len(results) > 0:
        auth_key = results[0].get("access_token")
        logging.info(f"JSON key:{auth_key}")
    else:
        error_string = f"Could not find an auth_key for team {team}" 
        logging.error(error_string)
        debug_log_error(error_string)
        return None

    return auth_key

def main(req: func.HttpRequest) -> func.HttpResponse:
    """
    Expects an object of type azure.functions.HttpRequest containing a JSON object.

    If the object contains a property `challenge`, this will simply return the value of the `challenge` property
    in a HttpResponse with code 200 (this is how Slack verifies that Apps are valid and alive).

    If the object contains a property `event`, this will call handle_event for further action.

    If JSON does not contain a `challenge` or `event`, return 400 - Bad Request.
    """    

    logging.info("YoStroop was triggered.")

    # Let's see if this was an OAUTH request - if so we handle it
    code = req.params.get("code")
    if code:
        logging.warning(f"Params: {req.params}")
        logging.warning(f"Code:{code}")
        return handle_oauth(code)

    # The request comes in a JSON
    try:
        req_body = req.get_json()        
    except ValueError:
        logging.warning(f"Not JSON: {req}")
        return handle_bad_request(req)

    if os.environ['YOSTROOP_DEBUG_LEVEL'] == "1":
        debug_log_event(req_body)

    # Let's determine from which team this trigger is coming
    team = req_body.get("team_id")
    if team:
        auth_token = get_team_key(team)
    else:
        logging.error(f"No team_id found in {req}")
        return handle_bad_request(req)


    # Dictionary.get returns None if the key does not exist
    challenge = req_body.get("challenge")
    event = req_body.get("event")

    if challenge:
        return func.HttpResponse (f"{challenge}", status_code = 200)
    elif event:
        return handle_slack_event(auth_token, event)
    else:
        return handle_bad_request(req)