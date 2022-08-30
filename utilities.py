import aiohttp
import asyncio
import requests
import pdfkit
from rich.console import Console
from rich.theme import Theme
from rich.panel import Panel
from rich.markdown import Markdown

cve_theme = Theme(
    {
        "good": "#42ef4f bold",
        "warning": "#feff00 bold",
        "bad": "#ff2222 bold",
        "rhb": "#ee0000 bold",
        "truwhite": "#ffffff",
    }
)


async def is_it_fixed_yet(text, input_err_message):
    """
    Parent function for the "/iify" Slack Command.
    Take in a CVE or group of CVEs (sanitized string from user) and uses
    the RH Security API to grab the associated meta data for each CVE and whether there is a fix.

    Args:
        text (str): A CVE or list a CVEs | Example: "CVE-XXXX-XXXXXX", "CVE-XXXX-XXXXXX CVE-XXXX-XXXXXX CVE-XXXX-XXXXXX"

    Returns:
        string: Returns a parsed CVE results in a code block format for Slack, or
        a flag to post a file to Slack because the length of the data is too long
        for a single message in Slack.
    """
    list_of_cves = iify_user_input_parser(text=text, input_err_message=input_err_message)
    if list_of_cves == input_err_message:
        return list_of_cves
    rhsa_results = await get_rhsa_data(list_of_cves=list_of_cves)
    rhsa_parsed_results = rhsa_data_parser(rhsa_results=rhsa_results, list_of_cves=list_of_cves)
    if len(str(rhsa_parsed_results)) < 3300:
        return iify_slack_output_formater(rhsa_parsed_results=rhsa_parsed_results, list_of_cves=list_of_cves)

    rhsa_results_output(rhsa_parsed_results, list_of_cves)
    return "use_html_file"


async def is_it_fixed_yet_preflight_check(results, client, body):
    """
    Take in the results and determines whether to send the data to the requester as
    plain text or a PDF file.
    """
    if results != "use_html_file" and body["channel_name"] != "directmessage":
        await client.chat_postMessage(channel=body["channel_id"], text=results)
    elif results != "use_html_file":
        await client.chat_postMessage(channel=body["user_id"], text=results)
    else:
        slack_comment = (
            "Your results are greater than 3300 characters.\nSo, here's your CVE lookup results as a PDF!  :smile:"
        )
        if body["channel_name"] != "directmessage":
            await client.files_upload(
                channels=body["channel_id"],
                initial_comment=slack_comment,
                file="./iify_results.pdf",
                title="iify_results.pdf",
                filename="iify_results.pdf",
                filetype="pdf",
            )
        else:
            await client.files_upload(
                channels=body["user_id"],
                initial_comment=slack_comment,
                file="./iify_results.pdf",
                title="iify_results.pdf",
                filename="iify_results.pdf",
                filetype="pdf",
            )


def iify_user_input_parser(text, input_err_message):
    """
    Takes in User supplied list of CVEs, verifies the input, pushes it to "get_rhsa_data()"

    Args:
        text (str): Takes in string for CVE(s) provide by a user.

    Returns:
        list: A list of deduped CVEs for lookup.
    """
    user_input_list = text.split(" ")
    list_of_cves = [item.upper() for item in user_input_list if item.upper().startswith("CVE-")]

    return list(dict.fromkeys(list_of_cves)) if list_of_cves else input_err_message


async def get_rhsa_data(list_of_cves):
    """
    Takes in list of CVEs and build the async API calls to retrieve RHSA data for each CVE.

    Args:
        list_of_cves (list): A list of CVEs for lookup against the RH Security API.

    Returns:
        list: A list of RHSA security data results for each provide CVE.
    """
    results = []
    urls = []
    for cve in list_of_cves:
        url = f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve}.json"
        urls.append(url)
    async with aiohttp.ClientSession() as session:
        tasks = get_tasks(session, urls)
        responses = await asyncio.gather(*tasks)
        for response in responses:
            results.append(await response.json())
    return results


def get_tasks(session, urls):
    """
    Creates async tasks for the RHSA API calls

    Args:
        session (ClientSession): Interface for make HTTP requests.
        urls (str): list of RHSA urls to pull security data from.

    Returns:
        list: A list of HTTP responses for each url in the list of RHSA urls provided.
    """
    return [session.get(url, ssl=True) for url in urls]


def rhsa_data_parser(rhsa_results, list_of_cves):
    """
    Takes in the returned RHSA API results, parses them, and returns a formatted version of the data

    Args:
        rhsa_results (list): List of RHSA Data
        list_of_cves (list): List of User provided CVEs

    Returns:
        list: List of parsed RHSA data that can be formatted easly for Slack.
    """
    results = []
    for cve in list_of_cves:
        for r in rhsa_results:
            if "bugzilla" in r.keys() and str(r["bugzilla"]["description"]).startswith(cve):
                if "affected_release" in r.keys():
                    for data in r["affected_release"]:
                        if data["product_name"] == "Red Hat Enterprise Linux 8":
                            parsed_string = (
                                f'\n{r["bugzilla"]["description"]}\n'
                                f'  > PRODUCT NAME: {data["product_name"]}\n'
                                f"  > RED HAT FIX STATE: Fixed\n"
                                f'  > RED HAT FIXED PACKAGE: {data["package"]}\n'
                            )
                            if "upstream_fix" in r.keys():
                                parsed_string += f'  > UPSTREAM FIX: {r["upstream_fix"]}\n'
                            else:
                                parsed_string += "  > UPSTREAM FIX: No Data\n"
                            parsed_string += (
                                f'  > ADVISORY: https://access.redhat.com/errata/{data["advisory"]}\n'
                                f'  > RELEASE DATE: {data["release_date"]}\n'
                                f'  > CPE: {data["cpe"]}\n\n'
                            )
                            results.append(parsed_string)
                if "package_state" in r.keys():
                    for data in r["package_state"]:
                        if data["product_name"] == "Red Hat Enterprise Linux 8":
                            parsed_string = (
                                f'\n{r["bugzilla"]["description"]}\n'
                                f'  > PRODUCT NAME: {data["product_name"]}\n'
                                f'  > RED HAT FIX STATE: {data["fix_state"]}\n'
                                f'  > RED HAT PACKAGE: {data["package_name"]}\n'
                            )
                            if "upstream_fix" in r.keys():
                                parsed_string += f'  > UPSTREAM FIX: {r["upstream_fix"]}\n'
                            else:
                                parsed_string += "  > UPSTREAM FIX: No Data\n"
                            parsed_string += f'  > CPE: {data["cpe"]}\n\n'
                            results.append(parsed_string)
        if cve not in str(results):
            results.append(f"{cve}\n  > No Data Found\n")
    return sorted(results)


def iify_slack_output_formater(rhsa_parsed_results, list_of_cves):
    """
    Takes in the list of CVEs and parsed RHSA results and formats them to be displayed in Slack.

    Args:
        rhsa_parsed_results (list): List of parsed RHSA data
        list_of_cves (list): List of User provided CVEs

    Returns:
        str: Returns parsed CVE results in a code block format for Slack.
    """
    return_str = ""
    for cve in list_of_cves:
        return_str += f"\n======================\n{cve}\n======================\n"
        return_str += "```"
        for results in rhsa_parsed_results:
            if cve in results:
                return_str += f"{results}"
        return_str += "```"
    return return_str


def rhsa_results_output(rhsa_parsed_results, list_of_cves):
    """
    Takes the final formatted version of the RHSA data and posted it to Slack as plain text,
    or writes that data to a PDF file depending on the length of the results.

    Args:
        rhsa_parsed_results (list): List of parsed RHSA data
        list_of_cves (list): List of User provided CVEs
    """
    console = Console(theme=cve_theme, record=True)
    panel_style = "#03fce3"
    with console.capture() as _:
        console.print(Markdown('# "IS IT FIXED YET?" RESULTS'), width=200)
        for cve in list_of_cves:
            results_output = ""
            for result in rhsa_parsed_results:
                if cve in result:
                    info = result.split("\n")
                    for item in info:
                        if "CVE" in item:
                            highlight = item.split(" ", 1)
                            results_output += f"\n[#ffffff][bold]{highlight[0]}[/] " + f"{highlight[-1]}\n"
                            continue
                        if "PACKAGE" in item:
                            highlight = item.split(":", 1)
                            results_output += f"{highlight[0]}:[bold #ffffff]{highlight[1]}[/]\n"
                            continue
                        if "Fixed" in item or "Not affected" in item or "Will not fix" in item:
                            highlight = item.split(":")
                            results_output += f"{highlight[0]}:[good]{highlight[1]}[/]\n"
                            continue
                        elif "Affected" in item:
                            highlight = item.split(":")
                            results_output += f"{highlight[0]}:[bad]{highlight[1]}[/]\n"
                            continue
                        elif "Under investigation" in item or "Fix deferred" in item or "Out of support scope" in item:
                            highlight = item.split(":")
                            results_output += f"{highlight[0]}:[warning]{highlight[1]}[/]\n"
                            continue
                        results_output += f"{item}\n"

            console.print(Panel(results_output, title=cve, title_align="left", width=200, style=panel_style))

    html_template = '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="UTF-8">\n \
    <style>\n{stylesheet}\nbody {{\n    color: #ffffff;\n    background-color: #2f3030;\n}}\n \
    </style>\n</head>\n<html>\n<body>\n <code>\n \
    <pre style="font-family:DejaVu Sans Mono"><font size="2">{code}</font></pre>\n    </code>\n</body>\n</html>\n'

    console.save_html(
        path="./iify_results.html",
        code_format=html_template,
    )
    try:
        config = pdfkit.configuration(wkhtmltopdf="/usr/bin/wkhtmltopdf")
        pdfkit.from_file("iify_results.html", "iify_results.pdf", configuration=config)
    except OSError:
        pdfkit.from_file("iify_results.html", "iify_results.pdf")


def get_newest_image_id(image_name):
    """
    Takes in User provided Container Image Name and used the RH Catalog API
    to look the newest image version's Catalog ID. Of the return RH Catalog API
    data we look at the last entry to get the data for the newest image.

    Args:
        image_name (str): User provided Container Image Name

    Returns:
        image_id, build_name, last_updated_timestamp
    """
    r = requests.get(
        f"https://catalog.redhat.com/api/containers/v1/"
        f"repositories/registry/registry.access.redhat.com/repository/{image_name}"
        f"/images?page_size=500&include=data._id,data.brew.build,data.architecture,data.last_update_date"
    )
    if r.status_code == 200:
        response = r.json()
        list_of_image_ids = [data["_id"] for data in response["data"] if data["architecture"] == "amd64"]
        for data in response["data"]:
            if data["_id"] == list_of_image_ids[-1]:
                return data["_id"], data["brew"]["build"], data["last_update_date"]


def get_catalog_rpm_data(image_id, err_message):
    """
    Uses the provide Catalog ID from "get_newest_image_id()" to get the RPM data
    for the Container Image.

    Args:
        image_id (str): The Catalog ID a a Container Image
        err_message (str): Predefined error message

    Returns:
        string: Return either a string containing the image RPM data, or a
        string stated the image data could not be found.
    """
    try:
        r = requests.get(f"https://catalog.redhat.com/api/containers/v1/images/id/{image_id}/rpm-manifest")
        if r.status_code == 200:
            response = r.json()
            rpm_data_list = [f"{rpms['nvra']}" for rpms in response["rpms"]]
            return "".join(f"{item}\n" for item in sorted(rpm_data_list))
    except KeyError:
        return err_message


def write_catalog_rpm_file(image_name, rpm_data, image_creation_date, image_tag):
    """
    Writes the collected Container Image data from RH Catalog to a txt file
    and push the file to Slack.

    Args:
        image_name (str): User provided Container Image Name.
        rpm_data (str): RH Catalog RPM data for a provide Container Image.
        image_creation_date (str): The new RH Catalog Create Date information for the provide Container Image.
        image_tag (list): List of Iamge Tag associated with a Container Image from RH Catalog.
    """
    results = (
        "============================================================\n"
        f"RPM data for the newest release of {image_name.upper()}\n\n"
        f"IMAGE LAST UPDATED: {image_creation_date.split('T')[0]}\n"
        f"IMAGE TAG(s): {image_tag}\n"
        "============================================================\n\n"
    )
    results += rpm_data
    with open("rpm_lookup.txt", "w") as f:
        f.write(results)


async def sbom_preflight_check(text, client, body):
    """
    Setup up the SBOM data to be sent to the requester.
    """
    slack_comment = f"Here are your RPM results for the newest release of `{text.upper()}`!  :smile:"
    if body["channel_name"] != "directmessage":
        await client.files_upload(
            channels=body["channel_id"],
            initial_comment=slack_comment,
            file="./rpm_lookup.txt",
            title="rpm_lookup.txt",
            filename="rpm_lookup.txt",
        )
    else:
        await client.files_upload(
            channels=body["user_id"],
            initial_comment=slack_comment,
            file="./rpm_lookup.txt",
            title="rpm_lookup.txt",
            filename="rpm_lookup.txt",
        )


def get_help_text():
    """Help text for the /iify help command in Slack

    Returns:
        str: Description of each iify slash command
    """
    return (
        "==============================\n"
        '*IIFY "/" (Slash) Commands*\n'
        "==============================\n\n"
        "`/iify` - This command gives back information on one or more CVEs\n\n"
        ">EXAMPLE: `/iffy cve-xxxx-xxxxx` or `/iffy cve-xxxx-xxxxx cve-xxxx-xxxxx cve-xxxx-xxxxx`\n\n\n"
        "`/sbom` - Provide a Container Image name from the Red Hat Catalog and get a listing of the image's included RPMs and their version.\n\n"
        ">NOTE: This will only provide the RPMs of newest version of the Container Image provided.\n"
        ">EXAMPLE: `/sbom ubi8/ubi` or `/sbom rhel8/python-38`\n\n\n"
        "`/iifyart` - Provides a random piece of ASCII art created by the man, the myth, the legend Kent Aycoth\n\n"
        ">EXAMPLE: n/a\n\n\n"
    )
