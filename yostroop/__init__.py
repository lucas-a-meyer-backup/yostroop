import logging
import requests
import os
import json
import sys
import urllib3
import azure.functions as func
import pydocumentdb
import pydocumentdb.document_client as document_client
import pydocumentdb.errors as errors
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

    logging.info(f"Attempting to transform userid {userid} into a username")
    logging.info(f"Using token {auth_token}")
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
        logging.info(f"The result was {r.status} and the name I found was: {name}")
        return name
    else:
        logging.warn(f"Something went wrong: {r.status}")
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
    logging.info(f"Uploading document to Cosmos DB")

    client, coll_string = get_cosmosdb_connection()
    client.CreateDocument(coll_string, payload)

def find_gift(team, sender, receiver, client_msg_id):
    logging.info(f"Trying to find if a gift already exists for client_msg_id {client_msg_id}")

    client, coll_string = get_cosmosdb_connection()
    logging.info(f"Client: {client}, String: {coll_string}")

    options = { 'enableCrossPartitionQuery': True }
    logging.info(options)

    query_str = f"select * from c where c.type = 'gift' and c.sender = '{sender}' and c.receiver = '{receiver}' and c.client_msg_id = '{client_msg_id}'"
    sql_query = {"query" : query_str }
    logging.info(sql_query)

    logging.info("Trying to query the database")
    try:
        results = list(client.QueryDocuments(coll_string, sql_query, options))
        if len(results) > 0:
            logging.info(f"Found {len(results)} results.")
            return True
        else:
            logging.info(f"Found {len(results)} results.")
            return False
    except Exception as e:
        logging.error(e)
        return False

def log_gift(team, sender, receiver, client_msg_id):
    """ 
    Creates and uploads a document of type gift to Yostroop's Cosmos DB
    """

    logging.info (f"Logging a gift from {sender} to {receiver} for client_msg_id {client_msg_id}")

    if find_gift(team, sender, receiver, client_msg_id):
        return 0

    gift = { 
             "type":"gift",
             "timestamp": str(datetime.utcnow()),
             "team": team,
             "sender": sender,
             "receiver": receiver,
             "client_msg_id": client_msg_id
            }

    send_document_cosmosdb(gift)

    return 1
  

def debug_log_event (event):
    """
    Uploads a document of type `event` to Yostroop's Cosmos DB
    """
    logging.info(f"Uploading event to database")
    logging.info(f"{event}")
    data = { 
             "type":"yostroop call",
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


def handle_slack_event(auth_token, team, event) -> func.HttpResponse:
    """
    Handles an object of the `event` type from Slack.
    For now, assumes all events are of type `message`. 

    It's triggered for all messages in a channel this bot is in.
    If the message contains a :stroopwafel: gift, we'll log it 
    to the database.
    """
    logging.info(f"Handling slack team {team} event:{event}")

    sender_id = event.get('user')
    message = event.get('text')
    channel = event.get('channel')
    client_msg_id = event.get('client_msg_id')
    subtype = event.get('subtype', "")

    if (sender_id is not None) and (message.find(":stroopwafel:") >= 0) and (subtype != "message_deleted"):
        
        logging.info("We're in a stroopwafel message!")
        recipient_names = list_gift_recipients(auth_token, message)
        sender = get_username_from_userid (auth_token, sender_id)

        recipient_count = 0
        # Save the gifts to the database:
        for recipient in recipient_names:
            if recipient:
                logging.info(f"Found recipient {recipient}, will log a gift")
                r = log_gift(team, sender, recipient, client_msg_id)
                recipient_count = recipient_count + r

        if recipient_count <= 0:
            return func.HttpResponse ("OK", status_code = 200)    
        elif recipient_count == 1:
            r = post_to_slack_channel (auth_token, f"user {sender} gave away a stroopwafel.", channel)
        else:
            r = post_to_slack_channel (auth_token, f"user {sender} gave away {recipient_count} stroopwafels.", channel)
        return func.HttpResponse (r._body, status_code = r.status)
    else:
        logging.info(f"Not a stroopwafel message")
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
        return func.HttpResponse (f"Installed new client", status_code = 302, 
            headers={"location":"https://github.com/RealLucasMeyer/yostroop/blob/master/InstallationComplete.md"})
    else:
        logging.error("Error in OAUTH")
        logging.error(r)
        return handle_bad_request(r)


def get_team_key(team):
    """
    Obtain an authorization key to use for this team for this session
    """
    client, coll_string = get_cosmosdb_connection()

    q = f"SELECT c.refresh_token FROM c WHERE c.team_id = '{team}'"
    query = { 'query': q }    

    logging.info(f"query: {q}")
    options = {} 
    options['enableCrossPartitionQuery'] = True
    options['maxItemCount'] = 1

    result_iterable = client.QueryDocuments(coll_string, query, options)
    results = list(result_iterable)

    if len(results) > 0:
        refresh_token = results[0].get("refresh_token")
        logging.info(f"JSON key:{refresh_token}")
    else:
        error_string = f"Could not find an auth_key for team {team}" 
        logging.error(error_string)
        debug_log_error(error_string)
        return None

    urllib3.disable_warnings()
    http = urllib3.PoolManager()
    logging.info(f"Refreshing token for client: {os.environ['YOSTROOP_OAUTH_CLIENT']}")
    logging.info(f"Refreshing token using secret: {os.environ['YOSTROOP_OAUTH_SECRET']}")
    logging.info(f"Refreshing token using secret: {refresh_token}")
    r = http.request(
        'POST',
        'https://slack.com/api/oauth.access',
        {
            "client_id": os.environ["YOSTROOP_OAUTH_CLIENT"],
            "client_secret": os.environ["YOSTROOP_OAUTH_SECRET"],
            "grant_type": "refresh_token",
            "refresh_token": refresh_token
        }
    )        

    if r.status == 200:
        body = json.loads(r._body)
        auth_key = body.get("access_token")
    else:
        logging.error("Could not refresh token")
        logging.error(r)
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
    logging.info(f"YoStroop debug level = {os.environ['YOSTROOP_DEBUG_LEVEL']}")

    # Let's see if this was an OAUTH request - if so we handle it
    code = req.params.get("code")
    if code:
        logging.info(f"Registration attempt with params: {req.params}")
        return handle_oauth(code)

    # The request comes in a JSON
    try:
        req_body = req.get_json()        
    except ValueError:
        logging.warning(f"Received something that was not JSON: {req}")
        return handle_bad_request(req)

    # If we're in debug mode, let's log what we were called with
    if os.environ['YOSTROOP_DEBUG_LEVEL'] == "1":
        debug_log_event(req_body)

    # If we got a JSON, let's see if it's a challenge. If it is, we answer and exit.
    challenge = req_body.get("challenge")
    if challenge:
        return func.HttpResponse (f"{challenge}", status_code = 200)

    # Let's determine from which team this trigger is coming
    team = req_body.get("team_id")
    if team:
        auth_token = get_team_key(team)
    else:
        logging.error(f"No team_id found in {req}")
        return handle_bad_request(req)

    # Let's make sure we got an event
    event = req_body.get("event")

    # If we got here, we really have an event, let's handle it
    if event:
        return handle_slack_event(auth_token, team, event)
    else:
        return handle_bad_request(req)