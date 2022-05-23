from aiohttp import request
import slack_sdk
import os
import ssl
import certifi
from pathlib import Path
from dotenv import load_dotenv
from flask import Flask, request, Response
from slackeventsapi import SlackEventAdapter

# Load Slack API key from .env file
env_path = Path(".") / ".env"
load_dotenv(dotenv_path=env_path)

app = Flask(__name__)
slack_event_adapter = SlackEventAdapter(os.environ["SIGNING_SECRET"], "/slack/events", app)

# Provide SSL Context from Certifi, and set up Slack Client
ssl_context = ssl.create_default_context(cafile=certifi.where())
client = slack_sdk.WebClient(token=os.environ["SLACK_TOKEN"], ssl=ssl_context)
bot_id = client.api_call("auth.test")["user_id"]


@app.route("/iify", methods=["POST"])
def iify():
    data = request.form
    print(data)
    user_id = data.get("user_id")
    channel_id = data.get("channel_id")
    channel_name = data.get("channel_name")
    if channel_name != "directmessage":
        client.chat_postMessage(channel=channel_name, text="I got your CVE for look up!")
    else:
        client.chat_postMessage(channel=user_id, text="I got your CVE for look up!")
    return Response(), 200


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
