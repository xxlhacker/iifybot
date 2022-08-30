import slack_sdk
import os
import ssl
import certifi
import bleach
import utilities
import logging
import ascii
import random
from rich.logging import RichHandler
from slack_bolt.app.async_app import AsyncApp


# Sets up Rich Logging
FORMAT = "%(message)s"
logging.basicConfig(level="INFO", format=FORMAT, datefmt="[%X]", handlers=[RichHandler()])
log = logging.getLogger("rich")


# Sets up the Async Slack app and uses the "SLACK_BOT_TOKEN" and "SIGNING_SECRET" environment variables.
if "SLACK_BOT_TOKEN" and "SIGNING_SECRET" in os.environ:
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    client = slack_sdk.web.async_client.AsyncWebClient(token=os.environ["SLACK_BOT_TOKEN"], ssl=ssl_context)
    app = AsyncApp(signing_secret=os.environ.get("SIGNING_SECRET"), client=client)
else:
    log.error(
        'App Failed to start. You must supply the "Slack Bot Token" and the "Slack Signing Secret" as environment variables.'
    )
    quit()


@app.command("/iify")
async def iify(ack, body, say, client):
    """
    The command take in one or more CVE (space separated) and return back information on the provides CVE(s).

    Returns:
        200 - Posts a Slack message with the associated CVE data as text or a PDF file.
    """
    log.info(body)
    await ack()
    input_err_message = "There were no CVE(s) provided in your command."
    if "text" in body:
        await say("Let me get that CVE data for you, hang tight!")
        sanitized_user_text = bleach.clean(body["text"])
        results = await utilities.is_it_fixed_yet(text=sanitized_user_text, input_err_message=input_err_message)
        if results == input_err_message:
            await say(input_err_message)
        else:
            await utilities.is_it_fixed_yet_preflight_check(results, client, body)
    else:
        await say(input_err_message)


@app.command("/sbom")
async def sbom(ack, body, say, client):
    """
    The command take in a Container Image name from the Red Hat Catalog and get a listing of the image's included RPMs and their version.

    Returns:
        200 - Posts a Slack message with the associated Image RPM data as a .txt file.
    """
    log.info(body)
    await ack()
    err_message = (
        "Sorry I could not find the image you where looking for. Did you format your Image Tag Correctly?\n"
        " - Example: `ubi8/ubi` or `rhel8/python-38`\n\n"
        "Additionally, the Catalog API may be experiencing issues. It may be worth checking...\n"
        " - RH Catalog: https://catalog.redhat.com/software/containers/search"
    )
    try:
        if "text" in body:
            await say("Let me get that SBOM data for you, hang tight!")
            sanitized_user_text = bleach.clean(str(body["text"]).lower())
            image_id, build_name, last_updated_timestamp = utilities.get_newest_image_id(
                image_name=sanitized_user_text
            )
            rpm_data = utilities.get_catalog_rpm_data(image_id=image_id, err_message=err_message)
            if rpm_data == err_message:
                await say(err_message)
            else:
                utilities.write_catalog_rpm_file(
                    image_name=sanitized_user_text,
                    rpm_data=rpm_data,
                    image_creation_date=last_updated_timestamp,
                    image_tag=build_name,
                )
            await utilities.sbom_preflight_check(text=sanitized_user_text, client=client, body=body)
        else:
            await say(err_message)
    except TypeError:
        await say(err_message)


@app.command("/iifyhelp")
async def iify_help(ack, body, say):
    """
    Command to get details on all the iify commands available

    Returns:
        A list of iify commands and their meanings
    """
    log.info(body)
    await ack()
    help_text = utilities.get_help_text()
    await say(help_text)


# global variable "pick" for making sure
# you don't get the same art twice in a row
pick = 0


@app.command("/iifyart")
async def art(ack, body, say):
    """
    Command to generate sweet ascii art or rotate through them all

    Returns:
        Sweet ascii art
    """
    log.info(body)
    await ack()
    global pick
    # data = request.form
    if "text" in body:
        sanitized_user_text = bleach.clean(str(body["text"]).lower())
        if sanitized_user_text == "all":
            for counter in range(1, 9):
                art = ascii.art(counter)
                await say(art)
                counter += 1
    else:
        newest_pick = random.choice([1, 2, 3, 4, 5, 6, 7])
        if newest_pick == pick:
            while newest_pick == pick:
                newest_pick = random.choice([1, 2, 3, 4, 5, 6, 7])
        pick = newest_pick
        art = ascii.art(pick)
        await say(art)


@app.command("/kent")
async def kent(ack, body, say):
    """
    Special command just for Casey

    Returns:
        A sweet message on the screen for Casey
    """
    log.info(body)
    await ack()
    art = ascii.art("kent")
    await say(art)


if __name__ == "__main__":
    app.start(port=5000, host="0.0.0.0", path="/slack/events")
