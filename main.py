from aiohttp import request
import slack_sdk
import os
import ssl
import certifi
import utilities
import bleach
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
client = slack_sdk.WebClient(token=os.environ["SLACK_BOT_TOKEN"], ssl=ssl_context)
bot_id = client.api_call("auth.test")["user_id"]


@app.route("/iify", methods=["POST"])
async def iify():
    data = request.form
    user_id = data.get("user_id")
    channel_id = data.get("channel_id")
    channel_name = data.get("channel_name")
    slack_comment = ":exclamation:Your results are greater than 3300 characters.\nSo, here's your CVE lookup results as a file! :smile:"
    results = await utilities.is_it_fixed_yet(text=data.get("text"))
    if results != "use_html_file":
        if channel_name != "directmessage":
            client.chat_postMessage(channel=channel_id, text=results)
        else:
            client.chat_postMessage(channel=user_id, text=results)
    else:
        if channel_name != "directmessage":
            client.files_upload(
                channels=channel_id,
                initial_comment=slack_comment,
                file="./iify_results.html",
                title="iify_results.html",
                filename="iify_results.html",
                filetype="html",
            )
        else:
            client.files_upload(
                channels=user_id,
                initial_comment=slack_comment,
                file="./iify_results.html",
                title="iify_results.html",
                filename="iify_results.html",
                filetype="html",
            )
    return Response(), 200


@app.route("/sbom", methods=["POST"])
def sbom():
    data = request.form
    user_id = data.get("user_id")
    channel_id = data.get("channel_id")
    channel_name = data.get("channel_name")
    sanitized_user_text = bleach.clean(data.get("text"))
    results = (
        "============================================================\n"
        f"Looking up RPMs data for the newest release of `{sanitized_user_text}`"
        "\n============================================================\n\n"
    )
    image_id = utilities.get_newest_image_id(image_tag=sanitized_user_text)
    results += utilities.get_catalog_rpm_data(image_id)
    if channel_name != "directmessage":
        client.chat_postMessage(channel=channel_id, text=results)
    else:
        client.chat_postMessage(channel=user_id, text=results)

    return Response(), 200


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
