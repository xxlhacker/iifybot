from aiohttp import request
import slack_sdk
import os
import ssl
import certifi
import utilities
import bleach
import logging
import ascii
import random
from rich.logging import RichHandler
from pathlib import Path
from dotenv import load_dotenv
from flask import Flask, request, Response
from slackeventsapi import SlackEventAdapter

# Rich Logging Setup
FORMAT = "%(message)s"
logging.basicConfig(level="INFO", format=FORMAT, datefmt="[%X]", handlers=[RichHandler()])
log = logging.getLogger("rich")

# Load Slack API key from .env file
env_path = Path(".") / ".env"
load_dotenv(dotenv_path=env_path)

app = Flask(__name__)
slack_event_adapter = SlackEventAdapter(os.environ["SIGNING_SECRET"], "/slack/events", app)

# Provide SSL Context from Certifi, and set up Slack Client
ssl_context = ssl.create_default_context(cafile=certifi.where())
client = slack_sdk.WebClient(token=os.environ["SLACK_BOT_TOKEN"], ssl=ssl_context)
bot_id = client.api_call("auth.test")["user_id"]


@app.route("/iify", methods=["POST"])
async def iify():
    data = request.form
    user_id = data.get("user_id")
    channel_id = data.get("channel_id")
    channel_name = data.get("channel_name")
    sanitized_user_text = bleach.clean(data.get("text"))
    log.info(f"USER: {data.get('user_name')} | COMMAND: /iffy | INPUT: {sanitized_user_text}", extra={"markup": True})
    results = await utilities.is_it_fixed_yet(text=sanitized_user_text)
    if results == "use_html_file":
        slack_comment = (
            "Your results are greater than 3300 characters.\nSo, here's your CVE lookup results as a PDF! :smile:"
        )
        if channel_name != "directmessage":
            client.files_upload(
                channels=channel_id,
                initial_comment=slack_comment,
                file="./iify_results.pdf",
                title="iify_results.pdf",
                filename="iify_results.pdf",
                filetype="pdf",
            )
        else:
            client.files_upload(
                channels=user_id,
                initial_comment=slack_comment,
                file="./iify_results.pdf",
                title="iify_results.pdf",
                filename="iify_results.pdf",
                filetype="pdf",
            )
    elif channel_name != "directmessage":
        client.chat_postMessage(channel=channel_id, text=results)
    else:
        client.chat_postMessage(channel=user_id, text=results)
    return Response(), 200


@app.route("/sbom", methods=["POST"])
def sbom():
    try:
        data = request.form
        user_id = data.get("user_id")
        channel_id = data.get("channel_id")
        channel_name = data.get("channel_name")
        sanitized_user_text = bleach.clean(data.get("text").lower())
        log.info(f"USER: {data.get('user_name')} | COMMAND: /sbom | INPUT: {sanitized_user_text}")
        image_id = utilities.get_newest_image_id(image_tag=sanitized_user_text)
        rpm_data = utilities.get_catalog_rpm_data(image_id)
        utilities.write_catalog_rpm_file(image_tag=sanitized_user_text, rpm_data=rpm_data)
        slack_comment = f"Here are you RPM results for the newest release of `{sanitized_user_text.upper()}`! :smile:"
        if channel_name != "directmessage":
            client.files_upload(
                channels=channel_id,
                initial_comment=slack_comment,
                file="./rpm_lookup.txt",
                title="rpm_lookup.txt",
                filename="rpm_lookup.txt",
            )
        else:
            client.files_upload(
                channels=user_id,
                initial_comment=slack_comment,
                file="./rpm_lookup.txt",
                title="rpm_lookup.txt",
                filename="rpm_lookup.txt",
            )
        return Response(), 200
    except TypeError:
        text = "Sorry I could not find the image you where looking for. Did you format your Image Tag Correctly?\n - Example: `ubi8/ubi` or `rhel8/python-38`"
        if channel_name != "directmessage":
            client.chat_postMessage(channel=channel_id, text=text)
        else:
            client.chat_postMessage(channel=user_id, text=text)
        return Response(), 200


@app.route("/iify_help", methods=["POST"])
def iify_help():
    data = request.form
    user_id = data.get("user_id")
    channel_id = data.get("channel_id")
    channel_name = data.get("channel_name")
    log.info(f"USER: {data.get('user_name')} | COMMAND: /iify_help | INPUT: N/A")
    help_text = utilities.get_help_text()
    if channel_name != "directmessage":
        client.chat_postMessage(channel=channel_id, text=help_text)
    else:
        client.chat_postMessage(channel=user_id, text=help_text)
    return Response(), 200

pick = 0

@app.route("/art", methods=["POST"])
def art():
    global pick
    newest_pick = random.choice([1, 2, 3, 4, 5, 6, 7])
    if newest_pick == pick:
        while newest_pick == pick:
            newest_pick = random.choice([1, 2, 3, 4, 5, 6, 7])
    pick = newest_pick
    data = request.form
    user_id = data.get("user_id")
    channel_id = data.get("channel_id")
    channel_name = data.get("channel_name")
    art = ascii.art(pick)  
    if channel_name != "directmessage":
        client.chat_postMessage(channel=channel_id, text=art)
    else:
        client.chat_postMessage(channel=user_id, text=art)
    return Response(), 200

@app.route("/kent", methods=["POST"])
def kent():
    data = request.form
    user_id = data.get("user_id")
    channel_id = data.get("channel_id")
    channel_name = data.get("channel_name")
    art = ascii.art(9)  
    if channel_name != "directmessage":
        client.chat_postMessage(channel=channel_id, text=art)
    else:
        client.chat_postMessage(channel=user_id, text=art)
    return Response(), 200

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
