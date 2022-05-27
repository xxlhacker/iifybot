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


async def is_it_fixed_yet(text: str):
    list_of_cves = iify_user_input_parser(text=text)
    rhsa_results = await get_rhsa_data(list_of_cves=list_of_cves)
    rhsa_parsed_results = rhsa_data_parser(rhsa_results=rhsa_results, list_of_cves=list_of_cves)
    if len(str(rhsa_parsed_results)) < 3300:
        return iify_slack_output_formater(rhsa_parsed_results=rhsa_parsed_results, list_of_cves=list_of_cves)

    rhsa_results_output(rhsa_parsed_results, list_of_cves)
    return "use_html_file"


# Take in User supplied list of CVEs, sanitizes the input, pushes it to "get_rhsa_data()"
def iify_user_input_parser(text: str):
    user_input_list = text.split(" ")
    list_of_cves = [item.upper() for item in user_input_list if item.upper().startswith("CVE")]

    return list(dict.fromkeys(list_of_cves))


# Takes in list of CVEs and build the async API calls to retrieve RHSA data for each CVE.
async def get_rhsa_data(list_of_cves):
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


# Creates async tasks for the RHSA API calls
def get_tasks(session, urls):
    return [session.get(url, ssl=True) for url in urls]


# Takes in the returned RHSA API results, parses them, and returns a formatted version of the data
def rhsa_data_parser(rhsa_results, list_of_cves):
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
        # If any CVE from the User's input is not present in the returned RHSA data,
        # it still call out that CVE, stating it does not having data via a string in the return 'results' data.
        if cve not in str(results):
            results.append(f"{cve}\n  > No Data Found\n")
    return sorted(results)


def iify_slack_output_formater(rhsa_parsed_results, list_of_cves):
    return_str = ""
    for cve in list_of_cves:
        return_str += f"\n======================\n{cve}\n======================\n"
        return_str += "```"
        for results in rhsa_parsed_results:
            if cve in results:
                return_str += f"{results}"
        return_str += "```"
    return return_str


# Takes the final formatted version of the RHSA data and prints it to the terminal,
# or writes that data to a file depending on the length of the results.
def rhsa_results_output(rhsa_parsed_results, list_of_cves):
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
    </style>\n</head>\n<html>\n<body>\n    <code>\n        <pre style="font-family:Menlo,\'DejaVu Sans Mono\',consolas, \
    \'Courier New\',monospace"><font size="2">{code}</font></pre>\n    </code>\n</body>\n</html>\n'

    console.save_html(
        path="./iify_results.html",
        code_format=html_template,
    )
    try:
        config = pdfkit.configuration(wkhtmltopdf='/usr/bin/wkhtmltopdf')
        pdfkit.from_file("iify_results.html", "iify_results.pdf", configuration=config)
    except OSError:
        pdfkit.from_file("iify_results.html", "iify_results.pdf")


def get_newest_image_id(image_name: str):
    r = requests.get(
        f"https://catalog.redhat.com/api/containers/v1/"
        f"repositories/registry/registry.access.redhat.com/repository/{image_name}/images?page_size=500"
    )
    if r.status_code == 200:
        response = r.json()
        creation_date_list = [data["creation_date"] for data in response["data"] if data["architecture"] == "amd64"]

        for data in response["data"]:
            if data["creation_date"] == sorted(creation_date_list)[-1]:
                for repository in data["repositories"]:
                    for signature in repository["signatures"]:
                        return data["_id"], sorted(creation_date_list)[-1], signature["tags"]


def get_catalog_rpm_data(image_id: str):
    try:
        r = requests.get(f"https://catalog.redhat.com/api/containers/v1/images/id/{image_id}/rpm-manifest")
        if r.status_code == 200:
            response = r.json()
            rpm_data_list = [f"{rpms['nvra']}" for rpms in response["rpms"]]
            return "".join(f"{item}\n" for item in sorted(rpm_data_list))
    except KeyError:
        return "Sorry I could not find the image you where looking for. Did you format your Image Tag Correctly?\n - Example: `ubi8/ubi`"


def write_catalog_rpm_file(image_name: str, rpm_data: str, image_creation_date: str, image_tag):
    results = (
        "============================================================\n"
        f"RPM data for the newest release of {image_name.upper()}\n\n"
        f"IMAGE RELEASE DATA: {image_creation_date.split('T')[0]}\n"
        f"IMAGE TAG(s): {image_tag}\n"
        "============================================================\n\n"
    )
    results += rpm_data
    with open("rpm_lookup.txt", "w") as f:
        f.write(results)


def get_help_text():
    return (
        "==============================\n"
        '*IIFY "/" (Slash) Commands*\n'
        "==============================\n\n"
        "`/iffy` - This command gives back information on one or more CVEs\n\n"
        ">EXAMPLE: `/iffy cve-xxxx-xxxxx` or `/iffy cve-xxxx-xxxxx cve-xxxx-xxxxx cve-xxxx-xxxxx`\n\n\n"
        "`/sbom` - Provide a Container Image name from the Red Hat Catalog and get a listing of the image's included RPMs and their version.\n\n"
        ">NOTE: This will only provide the RPMs of newest version of the Container Image provide.\n"
        ">EXAMPLE: `/sbom ubi8/ubi` or `/sbom rhel8/python-38`\n\n\n"
        "`/art` - Idk, it does art stuff that Kent made...\n\n"
        ">EXAMPLE: n/a\n\n\n"
    )
