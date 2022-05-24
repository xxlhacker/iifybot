import aiohttp
import asyncio
import os
import configparser
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
console = Console(theme=cve_theme)


async def is_it_fixed_yet(text: str):
    list_of_cves = iify_user_input_parser(text=text)
    rhsa_results = await get_rhsa_data(list_of_cves=list_of_cves)
    rhsa_parsed_results = rhsa_data_parser(rhsa_results=rhsa_results, list_of_cves=list_of_cves)
    if len(rhsa_parsed_results) > 10:
        rhsa_results_output(rhsa_parsed_results, list_of_cves)
        return 'use_html_file'
    else:
        results = iify_slack_output_formater(rhsa_parsed_results=rhsa_parsed_results, list_of_cves=list_of_cves)
        return results


# Take in User supplied list of CVEs, sanitizes the input, pushes it to "get_rhsa_data()"
def iify_user_input_parser(text: str):
    list_of_cves = []
    user_input_list = text.split(" ")
    for item in user_input_list:
        if item.upper().startswith("CVE"):
            list_of_cves.append(item.upper())
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
                                f'{r["bugzilla"]["description"]}\n'
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
                                f'{r["bugzilla"]["description"]}\n'
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
        return_str += f"======================\n{cve}\n======================\n"
        return_str += "```"
        for results in rhsa_parsed_results:
            if cve in results:
                return_str += f"{results}"
        return_str += "```"
    return return_str


# Takes the final formatted version of the RHSA data and prints it to the terminal,
# or writes that data to a file depending on the length of the results.
def rhsa_results_output(rhsa_parsed_results, list_of_cves):
    # config = configparser.ConfigParser()
    # config.read("config.ini")
    console = Console(theme=cve_theme, record=True)
    panel_style = "#03fce3"
    # file_path = os.path.join(os.getcwd(), f"{config['default']['OUTPUT_IS_IT_FIXED_FILE']}")
    console.print(Markdown('# "IS IT FIXED YET?" RESULTS'))
    # if len(rhsa_parsed_results) <= 10:
    # Takes results and splits then on new line characters
    # and highlights (aka colors) the CVE, Package, and Status
    # of the fix state for terminal output
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
        if len(rhsa_parsed_results) <= 10:
            console.print(Panel(results_output, title=cve, title_align="left", style=panel_style))
        else:
            with console.capture() as _:
                console.print(Panel(results_output, title=cve, title_align="left", style=panel_style))
    if len(rhsa_parsed_results) > 10:
        html_template = '<!DOCTYPE html>\n<head>\n<meta charset="UTF-8">\n \
        <style>\n{stylesheet}\nbody {{\n    color: #ffffff;\n    background-color: #2f3030;\n}}\n \
        </style>\n</head>\n<html>\n<body>\n    <code>\n        <pre style="font-family:Menlo,\'DejaVu Sans Mono\',consolas, \
        \'Courier New\',monospace"><font size="2">{code}</font></pre>\n    </code>\n</body>\n</html>\n'
        
        console.save_html(
            path="./iify_results.html",
            code_format=html_template,
        )
        # console.print(f"   > Results have been save a [good]{file_path}[/]")
