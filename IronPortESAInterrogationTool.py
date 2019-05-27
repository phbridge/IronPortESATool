# Title
# Iron Port ESA Interrogation Tool
#
# Language
# Python 3.5
#
# Description
# This script will load search results containing a number of emails. It will then parse the message detail section
# and add the details to a CSV file for use later on.
#
# Contacts
# Phil Bridges - phbridge@cisco.com
#
# EULA
# This software is provided as is and with zero support level. Support can be purchased by providing Phil bridges
# with a variety of Beer, Wine, Steak and Greggs pasties. Please contact phbridge@cisco.com for support costs and
# arrangements. Until provision of alcohol or baked goodies your on your own but there is no rocket science
# involved so dont panic too much. To accept this EULA you must include the correct flag when running the script.
# If this script goes crazy wrong and breaks everything then your also on your own and Phil will not accept any
# liability of any type or kind. As this script belongs to Phil and NOT Cisco then Cisco cannot be held
# responsible for its use or if it goes bad, nor can Cisco make any profit from this script. Phil can profit
# from this script but will not assume any liability. Other than the boring stuff please enjoy and plagiarise
# as you like (as I have no ways to stop you) but common courtesy says to credit me in some way.
# [see above comments on Beer, Wine, Steak and Greggs.].
#
# Version Control               Comments
# Version 0.01 Date 20/11/18     Inital draft
# Version 0.1  Date 22/11/18     First working draft ready for export
# Version 0.2  Date 23/11/18     Added more error handling and debugging
# Version 0.3  Date 26/11/18     Added more error handling and debugging
# Version 0.4  Date 27/11/18     Added more error handling and debugging
# Version 0.5  Date 28/11/18     Added more error handling and debugging
# Version 0.6  Date 29/11/18     Added more error handling and debugging
# Version 0.7  Date 03/12/18     Added more error handling and debugging
# Version 0.8  Date 03/12/18     Change the output so to not strip white spaces from attachment filename.
# Version 0.9  Date 10/12/18     Added handling of CSRF to avoid the application error thing (hopefully)
# Version 0.10 Date 10/12/18     Tidied up bits of the code
# Version 0.11 Date 18/12/18     Made some changes around output formatting
#
# Version 6.9 Date xx/xx/xx     Took over world and actually got paid for value added work....
#                               If your reading this approach me on LinkedIn for details of weekend "daily" rate
# Version 7.0 Date xx/xx/xx     Note to the Gaffer - if your reading this then the above line is a joke only :-)
#
# ToDo *******************TO DO*********************
# 1.0 DONE Inital Draft
# 2.0 Web Counter
# 3.0 DONE Remove email address
# 4.0 Tidy up logging and error handling
#
#

import argparse                 # needed for the nice menus and variable checking
from datetime import datetime   # needed for the datetime for filename
import requests                 # for all the http/https stuff
import urllib.parse             # convert string to url encoded string
import re                       # regular expresssion matching for finding urls
from bs4 import BeautifulSoup   # bs4 used mostly to remove tags for nice access to data
import time                     # used for sleeping
import sys                      # Error handling


def parse_input_arguments():
    parser = argparse.ArgumentParser(description='process input')
    parser.add_argument("-ACCEPTEULA", "--acceptedeula", action='store_true', default=False,
                        help="Marking this flag accepts EULA embedded withing the script")
    parser.add_argument("-u", "--username", required=True, default="test@test.com",
                        help="username to use to login to the portal")
    parser.add_argument("-p", "--password", required=True, default="password",
                        help="password used to loginto the portal")
    parser.add_argument("-v", "--verbose", action='store_true', default=False,
                        help="increase output verbosity", )
    parser.add_argument("-y", "--proxy", required=False, default=False,
                        help="define a proxy for both http and https if required", )
    parser.add_argument("-s", "--search", required=False, default="",
                        help='search string to use to filter emails')
    parser.add_argument("-e", "--esa_address", required=True, default="",
                        help='IP or URL of ESA appliance')
    args = parser.parse_args()
    if not args.acceptedeula:
        print("""you need to accept the EULA agreement which is as follows:-
    # EULA
    # This software is provided as is and with zero support level. Support can be purchased by providing Phil bridges with a
    # varity of Beer, Wine, Steak and Greggs pasties. Please contact phbridge@cisco.com for support costs and arrangements.
    # Until provison of alcohol or baked goodies your on your own but there is no rocket sciecne involved so dont panic too
    # much. To accept this EULA you must include the correct flag when running the script. If this script goes crazy wrong and
    # breaks everything then your also on your own and Phil will not accept any liability of any type or kind. As this script
    # belongs to Phil and NOT Cisco then Cisco cannot be held responsable for its use or if it goes bad, nor can Cisco make
    # any profit from this script. Phil can profit from this script but will not assume any liability. Other than the boaring
    # stuff please enjoy and plagerise as you like (as I have no ways to stop you) but common curtacy says to credit me in some
    # way [see above comments on Beer, Wine, Steak and Greggs.].
    
    # To accept the EULA please run with the -ACCEPTEULA flag
        """)
        quit()

    if args.verbose:
        print("-v Verbose flag set printing extended ouput")
    print("Arguments and files loaded")
    if args.verbose:
        print(str(args.username))
        print(str(args.proxy))
        print(str(args.search))
        print(str(args.verbose))
        print(str(args.esa_address))
    return args


def create_logfile():
    try:
        output_filename = str(datetime.now()) + "-IronPortESAInterrogationTool"
        output_log = open(str(output_filename) + ".text", 'a+')
        output_log.write(str(datetime.now()) + "     " + "log file created sucessfully file name should be " +
                         str(output_filename) + "\n")
    except:
        print("something went bad opening/creating file for writing")
        print("Unexpected error:", sys.exc_info()[0])
        quit()
    return output_log


def set_proxy_if_needed():
    print("setting proxy")
    if not args.proxy:
        if args.verbose:
            print("no proxy settings detected")
        output_log.write(str(datetime.now()) + "     " + "no proxy settings detected " + "\n")
    else:
        use_proxies = {
            'http': 'http://' + args.proxy,
            'https': 'http://' + args.proxy,
        }
        if args.verbose:
            print("proxy flag detected setting proxies")
            print(use_proxies)
        output_log.write(str(datetime.now()) + "     " + "proxy settings found and used " + "\n")
        return use_proxies
    return


def check_access_to_esa():
    esa_url = "".join("https://" + str(args.esa_address) + "/login")
    try:
        esa_session = get_login_to_esa(esa_url, True)
    except requests.HTTPError as e:
        print("Checking ESA connection failed, status code {0}.".format(e.response.status_code))
        output_log.write(str(datetime.now()) + "     " +
                         "Checking internet connection failed, status code {0}.".format(e.response.status_code) + "\n")
        quit()
    except requests.ConnectionError:
        print("No internet connection available.")
        output_log.write(str(datetime.now()) + "     " + "No internet connection available." + "\n")
        quit()
    return esa_session


def get_login_to_esa(esa_url, check_only):
    esa_url = "".join("https://" + str(args.esa_address) + "/login")
    if check_only:
        esa_session = requests.session()
    output_log.write(str(datetime.now()) + "     " + "Fetching " + esa_url + "\n")
    if not args.proxy:
        connection_check = esa_session.get(esa_url, timeout=5, verify=False)
    else:
        connection_check = esa_session.get(esa_url, timeout=5, proxies=proxy_server_to_use, verify=False)

    output_log.write(str(datetime.now()) + "     " + str(connection_check.status_code) + "\n")
    #
    output_log.write(str(datetime.now()) + "     " + str(connection_check.text) + "\n")
    #
    # HTTP errors are not raised by default, this statement does that
    connection_check.raise_for_status()

    if connection_check.status_code == 200:
        print("Response from Login splash looking good moving forwards Response was 200 OK")
        output_log.write(str(datetime.now()) + "     " + "ESA connection found proceding" + "\n")
        # todo add something here to check content not burp error splash 200 ok
        if check_only:
            connection_check.close()
    else:
        print("something might not be quite right")
        print(str(connection_check.status_code))
        output_log.write(str(datetime.now()) + "     " + "something might not be quite right" + "\n")
        output_log.write(str(datetime.now()) + "     " + str(connection_check.status_code) + "\n")
        quit()
    return esa_session


def login_to_esa():
    esa_login_url = "".join("https://" + str(args.esa_address) + "/login")
    login_post_payload = "action=Login&referrer=&screen=login" + \
                         "&username=" + urllib.parse.quote_plus(args.username) + \
                         "&password=" + urllib.parse.quote_plus(args.password)
    login_post_headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/38.0 Iceweasel/38.6.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-GB,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Referer": "https://" + str(args.esa_address) + "/login",
        "Connection": "close",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    output_log.write(str(datetime.now()) + "     " + "Fetching " + esa_login_url + "\n")
    if not args.proxy:
        login_post_send = esa_session.post(esa_login_url, headers=login_post_headers, data=login_post_payload)
    else:
        login_post_send = esa_session.post(esa_login_url, headers=login_post_headers, data=login_post_payload,
                                           verify=False, proxies=proxy_server_to_use)
    output_log.write(str(datetime.now()) + "     " + str(login_post_send.status_code) + "\n")
    output_log.write(str(datetime.now()) + "     " + str(login_post_send.text) + "\n")
    csrf_key_latest_regex = re.search(r'<script type="text/javascript" src="https://' + re.escape(str(args.esa_address)) + '/javascript\?(.*)&language=en-us"></script>', login_post_send.text, re.DOTALL)
    csrf_key_latest = "".join("&" + str(csrf_key_latest_regex.group(1)))
    print("Setting latest CSRF = " + csrf_key_latest)
    output_log.write(str(datetime.now()) + "     " + "Setting latest CSRF" + csrf_key_latest + "\n")
    print(str(csrf_key_latest))
    global csrf_key_origional
    if csrf_key_origional == "":
        csrf_key_origional = "".join("&" + str(csrf_key_latest_regex.group(1)))
        print("setting origional CSRF = " + csrf_key_origional)
        output_log.write(str(datetime.now()) + "     " + "setting origional CSRF" + csrf_key_origional + "\n")
    global csrf_key_latest


def run_query_to_get_detailed_links(start_day, start_month, start_year, end_day, end_month, end_year, page_number):
    esa_message_tracking_url = "".join("https://" + str(args.esa_address) + "/monitor_email_tracking/message_tracking")
    # TODO REMOVE THIS ADDRESS!!!!!!!!
    # TODO REMOVE THIS ADDRESS!!!!!!!!
    # TODO REMOVE THIS ADDRESS!!!!!!!!
    query_post_payload = "action=Search&canned=&sender_match=match_begins" \
                         "&sender=" + "" \
                         "&recipient_match=match_begins&recipient=&subject_match=match_begins" \
                         "&subject=&timerange=custom" \
                         "&date_from=" + str(start_month) + "%2F" + str(start_day) + "%2F" + str(start_year) + "&time_from=00%3A01" \
                         "&date_to=" + str(end_month) + "%2F" + str(end_day) + "%2F" + str(end_year) + "&time_to=00%3A01" \
                         "&sender_ip=&search_type=messages&attachment_match=match_contains&attachment=" \
                         "&file_sha256=&url_clicked=&macro_filter_type%5B%5D=incoming" \
                         "&macro_filter_type%5B%5D=outgoing&quarantine_name=&message_filter_name=&fed_dict_entry=" \
                         "&content_filter_name=&content_filter_type%5B%5D=incoming&content_filter_type%5B%5D=outgoing" \
                         "&dmarc_domain_from=&dlp_policy=&message_id=&mid=&host=&query_timeout=600&max_results=1000&" + \
                         "pg=" + str(page_number) + "&pageSize=250" \
                         "&range_day=" + "11%2F19%2F2018%7C16%3A00%7C11%2F20%2F2018%7C16%3A05" \
                         "&range_week=" + "11%2F13%2F2018%7C00%3A00%7C11%2F20%2F2018%7C16%3A05" + \
                         csrf_key_latest
    query_post_headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/38.0 Iceweasel/38.6.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-GB,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Referer": "https://" + str(args.esa_address) + "/monitor_email_tracking/message_tracking",
        "Connection": "close",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    output_log.write(str(datetime.now()) + "     " + "Fetching " + esa_message_tracking_url + "\n")
    if not args.proxy:
        query_post_send = esa_session.post(esa_message_tracking_url, timeout=605, headers=query_post_headers, data=query_post_payload)
    else:
        query_post_send = esa_session.post(esa_message_tracking_url, timeout=605, headers=query_post_headers, data=query_post_payload,
                                           verify=False, proxies=proxy_server_to_use)
    output_log.write(str(datetime.now()) + "     " + str(query_post_send.status_code) + "\n")
    detail_url_hunter = re.compile(r'https://' + re.escape(str(args.esa_address)) + '/monitor_email_tracking/message_tracking*(.*)')
    for line in query_post_send.text.splitlines():
        found_url = detail_url_hunter.findall(line)
        if not found_url == []:
            for i in found_url:
                print(str(i))
                detail_url_hunter_array_raw.append("https://" + str(args.esa_address) + "/monitor_email_tracking/message_tracking" + str(i).split("'")[0])
                output_log.write(str(datetime.now()) + "     " + "https://" + str(args.esa_address) + "/monitor_email_tracking/message_tracking" + str(i).split("'")[0] + "\n")

    print("so far found " + str(len(detail_url_hunter_array_raw)) + " URL's that will be collected.")
    print("the last date ran was " + "From " + str(start_month) + "/" + str(start_day) + "/" + str(start_year) +
          "  To " + str(end_month) + "/" + str(end_day) + "/" + str(end_year))

    output_log.write(str(datetime.now()) + "     " + "so far found " + str(len(detail_url_hunter_array_raw)) + " URL's that will be collected" + "\n")
    output_log.write(str(datetime.now()) + "     " + "the last date ran was " + "From " + str(start_month) + "/" + str(start_day) + "/" + str(start_year) +
                     "  To " + str(end_month) + "/" + str(end_day) + "/" + str(end_year) + "\n")
    return


def collect_message_url():
    year_start = 2018
    year_end = 2018
    month_end = 1
    for month_start in range(1, 13):
        day_start = 1
        day_end = 7
        output_log.write(str(datetime.now()) + "     " +
                         str(day_start) + "," +
                         str(month_start) + "," +
                         str(year_start) + "," +
                         str(day_end) + "," +
                         str(month_end) + "," +
                         str(year_end) + "," + "\n")
        for x in range(1, 5):
            run_query_to_get_detailed_links(day_start, month_start, year_start, day_end, month_end, year_end, x)
            output_log.flush()

        day_start = 7
        day_end = 14
        output_log.write(str(datetime.now()) + "     " +
                         str(day_start) + "," +
                         str(month_start) + "," +
                         str(year_start) + "," +
                         str(day_end) + "," +
                         str(month_end) + "," +
                         str(year_end) + "," + "\n")
        for x in range(1, 5):
            run_query_to_get_detailed_links(day_start, month_start, year_start, day_end, month_end, year_end, x)
            output_log.flush()

        day_start = 14
        day_end = 21
        output_log.write(str(datetime.now()) + "     " +
                         str(day_start) + "," +
                         str(month_start) + "," +
                         str(year_start) + "," +
                         str(day_end) + "," +
                         str(month_end) + "," +
                         str(year_end) + "," + "\n")
        for x in range(1, 5):
            run_query_to_get_detailed_links(day_start, month_start, year_start, day_end, month_end, year_end, x)
            output_log.flush()

        month_end = month_start + 1
        day_start = 21
        day_end = 1
        output_log.write(str(datetime.now()) + "     " +
                         str(day_start) + "," +
                         str(month_start) + "," +
                         str(year_start) + "," +
                         str(day_end) + "," +
                         str(month_end) + "," +
                         str(year_end) + "," + "\n")
        for x in range(1, 5):
            run_query_to_get_detailed_links(day_start, month_start, year_start, day_end, month_end, year_end, x)
            output_log.flush()

        if month_start == 12:
            year_end += 1
            month_end = 1


def collect_message_details_and_parse():
    query_post_headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/38.0 Iceweasel/38.6.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-GB,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Referer": "https://" + str(args.esa_address) + "/monitor_email_tracking/message_tracking",
        "Connection": "close",
    }
    # "Content-Type": "application/x-www-form-urlencoded",
    working_url_counter = 0
    working_url_total_size = len(detail_url_hunter_array_raw)
    print("Working or URL " + str(working_url_counter) + "of " + str(working_url_total_size))

    for message_details_url in detail_url_hunter_array_raw:
        output_log.write(str(datetime.now()) + "     " + message_details_url + "\n")
        if "ExportCSV" in message_details_url:
            print("Export found in URL skipping")
            output_log.write(str(datetime.now()) + "     " + "Export found in URL skipping" + "\n")
            continue
        output_log.write(str(datetime.now()) + "     " + "Fetching " + message_details_url.replace(csrf_key_origional, csrf_key_latest) + "\n")
        try:
            if not args.proxy:
                message_details = esa_session.get(message_details_url.replace(csrf_key_origional, csrf_key_latest),
                                                  timeout=605, headers=query_post_headers)
            else:
                message_details = esa_session.get(message_details_url.replace(csrf_key_origional, csrf_key_latest),
                                                  timeout=605, headers=query_post_headers,
                                                   verify=False, proxies=proxy_server_to_use)
        except requests.HTTPError as e:
            print("################### PANIC PANIC PACNIC####################")
            print("################### PANIC PANIC PACNIC####################")
            print("################### PANIC PANIC PACNIC####################")
            print("Requests message_detials bombed out, status code {0}.".format(e.response.status_code))
            output_log.write(str(datetime.now()) + "     " +
                             "Requests message_detials bombed out, status code {0}.".format(e.response.status_code) + "\n")
            output_log.write(
                str(datetime.now()) + "     " + "######### THIS ONE FAILED ##########" + message_details_url.replace(
                    csrf_key_origional, csrf_key_latest) + "\n")
            try:
                print("session timed out (maybe) trying to log back in")
                output_log.write(str(datetime.now()) + "     " + "session timed out (maybe) trying to log back in" + "\n")
                soupped_message_details_error = BeautifulSoup(message_details.text, "html.parser")
                if "User Session is not valid." in str(soupped_message_details_error.text):
                    print("found User Session is not valid. in text")
                    output_log.write(str(datetime.now()) + "     " + "found User Session is not valid. in text" + "\n")
                    esa_session.close()
                    print("killed old session")
                    output_log.write(str(datetime.now()) + "     " + "killed old session" + "\n")
                    check_access_to_esa()
                    print("access checked")
                    output_log.write(str(datetime.now()) + "     " + "access checked" + "\n")
                    login_to_esa()
                    print("loged in ok (I THINK)")
                    output_log.write(str(datetime.now()) + "     " + "loged in ok (I THINK)" + "\n")
                elif "process of restarting" in str(soupped_message_details_error.text):
                    print("process of restarting in text")
                    output_log.write(
                        str(datetime.now()) + "     " + "found process of restarting in text" + "\n")
                    time.sleep(300)
                    esa_session.close()
                    print("killed old session")
                    output_log.write(str(datetime.now()) + "     " + "killed old session" + "\n")
                    check_access_to_esa()
                    print("access checked")
                    output_log.write(str(datetime.now()) + "     " + "access checked" + "\n")
                    login_to_esa()
                    print("loged in ok (I THINK)")
                    output_log.write(str(datetime.now()) + "     " + "loged in ok (I THINK)" + "\n")
                elif "Application Error" in str(soupped_message_details_error.text):
                    print("Application Error in text")
                    output_log.write(
                        str(datetime.now()) + "     " + "found Application Error in text" + "\n")
                    time.sleep(300)
                    esa_session.close()
                    print("killed old session")
                    output_log.write(str(datetime.now()) + "     " + "killed old session" + "\n")
                    check_access_to_esa()
                    print("access checked")
                    output_log.write(str(datetime.now()) + "     " + "access checked" + "\n")
                    login_to_esa()
                    print("loged in ok (I THINK)")
                    output_log.write(str(datetime.now()) + "     " + "loged in ok (I THINK)" + "\n")
                else:
                    print("""couldnt find "User Session is not valid." OR "process of restarting" OR "process of 
                    restarting" in string to handle""")
                    output_log.write(str(datetime.now()) + "     " + """couldnt find "User Session is not valid." 
                    OR "process of restarting" OR "process of restarting" in string to handle""" + "\n")
            except:
                print("something else bad happened didnt find string in text")
                output_log.write(str(datetime.now()) + "     " + "something else bad happened didnt find string in text" + "\n")
            continue
        except requests.ConnectionError:
            print("################### PANIC PANIC PACNIC####################")
            print("################### PANIC PANIC PACNIC####################")
            print("################### PANIC PANIC PACNIC####################")
            print("Requests message_detials bombed out.")
            output_log.write(str(datetime.now()) + "     " + "Requests message_detials bombed out." + "\n")
            output_log.write(
                str(datetime.now()) + "     " + "######### THIS ONE FAILED ##########" + message_details_url.replace(
                    csrf_key_origional, csrf_key_latest) + "\n")
            try:
                print("session timed out (maybe) trying to log back in")
                output_log.write(str(datetime.now()) + "     " + "session timed out (maybe) trying to log back in" + "\n")
                soupped_message_details_error = BeautifulSoup(message_details.text, "html.parser")
                if "User Session is not valid." in str(soupped_message_details_error.text):
                    print("found User Session is not valid. in text")
                    output_log.write(str(datetime.now()) + "     " + "found User Session is not valid. in text" + "\n")
                    esa_session.close()
                    print("killed old session")
                    output_log.write(str(datetime.now()) + "     " + "killed old session" + "\n")
                    check_access_to_esa()
                    print("access checked")
                    output_log.write(str(datetime.now()) + "     " + "access checked" + "\n")
                    login_to_esa()
                    print("loged in ok (I THINK)")
                    output_log.write(str(datetime.now()) + "     " + "loged in ok (I THINK)" + "\n")
                elif "process of restarting" in str(soupped_message_details_error.text):
                    print("process of restarting in text")
                    output_log.write(
                        str(datetime.now()) + "     " + "found process of restarting in text" + "\n")
                    time.sleep(300)
                    esa_session.close()
                    print("killed old session")
                    output_log.write(str(datetime.now()) + "     " + "killed old session" + "\n")
                    check_access_to_esa()
                    print("access checked")
                    output_log.write(str(datetime.now()) + "     " + "access checked" + "\n")
                    login_to_esa()
                    print("loged in ok (I THINK)")
                    output_log.write(str(datetime.now()) + "     " + "loged in ok (I THINK)" + "\n")
                elif "Application Error" in str(soupped_message_details_error.text):
                    print("Application Error in text")
                    output_log.write(
                        str(datetime.now()) + "     " + "found Application Error in text" + "\n")
                    time.sleep(300)
                    esa_session.close()
                    print("killed old session")
                    output_log.write(str(datetime.now()) + "     " + "killed old session" + "\n")
                    check_access_to_esa()
                    print("access checked")
                    output_log.write(str(datetime.now()) + "     " + "access checked" + "\n")
                    login_to_esa()
                    print("loged in ok (I THINK)")
                    output_log.write(str(datetime.now()) + "     " + "loged in ok (I THINK)" + "\n")
                else:
                    print("""couldnt find "User Session is not valid." OR "process of restarting" OR "process of 
                    restarting" in string to handle""")
                    output_log.write(str(datetime.now()) + "     " + """couldnt find "User Session is not valid." 
                    OR "process of restarting" OR "process of restarting" in string to handle""" + "\n")
            except:
                print("something else bad happened didnt find string in text")
                output_log.write(str(datetime.now()) + "     " + "something else bad happened didnt find string in text" + "\n")
            continue
        except:
            print("################### PANIC PANIC PACNIC####################")
            print("################### PANIC PANIC PACNIC####################")
            print("################### PANIC PANIC PACNIC####################")
            output_log.write(
                str(datetime.now()) + "     " + "################### PANIC PANIC PACNIC####################" + "\n")
            output_log.write(
                str(datetime.now()) + "     " + "################### PANIC PANIC PACNIC####################" + "\n")
            output_log.write(
                str(datetime.now()) + "     " + "################### PANIC PANIC PACNIC####################" + "\n")
            output_log.write(
                str(datetime.now()) + "     " + "################### SOEMTHING BAD HAPPEND DURING MESSAGE LOAD ####################" + "\n")
            output_log.write(
                str(datetime.now()) + "     " + str(message_details.status_code) + "\n")
            output_log.write(
                str(datetime.now()) + "     " + str(message_details.text) + "\n")
            output_log.write(
                str(datetime.now()) + "     " + "######### THIS ONE FAILED ##########" + message_details_url.replace(csrf_key_origional, csrf_key_latest) + "\n")
            output_log.write(
                str(datetime.now()) + "     " + "######### THIS ONE FAILED ##########" + message_details_url.replace(csrf_key_origional, csrf_key_latest) + "\n")
            output_log.write(
                str(datetime.now()) + "     " + "######### THIS ONE FAILED ##########" + message_details_url.replace(csrf_key_origional, csrf_key_latest) + "\n")
            output_log.write(
                str(datetime.now()) + "     " + "######### THIS ONE FAILED ##########" + message_details_url.replace(csrf_key_origional, csrf_key_latest) + "\n")
            output_log.write(
                str(datetime.now()) + "     " + "######### THIS ONE FAILED ##########" + message_details_url.replace(csrf_key_origional, csrf_key_latest) + "\n")
            try:
                print("session timed out (maybe) trying to log back in")
                output_log.write(str(datetime.now()) + "     " + "session timed out (maybe) trying to log back in" + "\n")
                soupped_message_details_error = BeautifulSoup(message_details.text, "html.parser")
                if "User Session is not valid." in str(soupped_message_details_error.text):
                    print("found User Session is not valid. in text")
                    output_log.write(str(datetime.now()) + "     " + "found User Session is not valid. in text" + "\n")
                    esa_session.close()
                    print("killed old session")
                    output_log.write(str(datetime.now()) + "     " + "killed old session" + "\n")
                    check_access_to_esa()
                    print("access checked")
                    output_log.write(str(datetime.now()) + "     " + "access checked" + "\n")
                    login_to_esa()
                    print("loged in ok (I THINK)")
                    output_log.write(str(datetime.now()) + "     " + "loged in ok (I THINK)" + "\n")
                elif "process of restarting" in str(soupped_message_details_error.text):
                    print("process of restarting in text")
                    output_log.write(
                        str(datetime.now()) + "     " + "found process of restarting in text" + "\n")
                    time.sleep(300)
                    esa_session.close()
                    print("killed old session")
                    output_log.write(str(datetime.now()) + "     " + "killed old session" + "\n")
                    check_access_to_esa()
                    print("access checked")
                    output_log.write(str(datetime.now()) + "     " + "access checked" + "\n")
                    login_to_esa()
                    print("loged in ok (I THINK)")
                    output_log.write(str(datetime.now()) + "     " + "loged in ok (I THINK)" + "\n")
                elif "Application Error" in str(soupped_message_details_error.text):
                    print("Application Error in text")
                    output_log.write(
                        str(datetime.now()) + "     " + "found Application Error in text" + "\n")
                    time.sleep(300)
                    esa_session.close()
                    print("killed old session")
                    output_log.write(str(datetime.now()) + "     " + "killed old session" + "\n")
                    check_access_to_esa()
                    print("access checked")
                    output_log.write(str(datetime.now()) + "     " + "access checked" + "\n")
                    login_to_esa()
                    print("loged in ok (I THINK)")
                    output_log.write(str(datetime.now()) + "     " + "loged in ok (I THINK)" + "\n")
                else:
                    print("""couldnt find "User Session is not valid." OR "process of restarting" OR "process of 
                    restarting" in string to handle""")
                    output_log.write(str(datetime.now()) + "     " + """couldnt find "User Session is not valid." 
                    OR "process of restarting" OR "process of restarting" in string to handle""" + "\n")
            except:
                print("something else bad happened didnt find string in text")
                output_log.write(str(datetime.now()) + "     " + "something else bad happened didnt find string in text" + "\n")
            continue
        output_log.write(str(datetime.now()) + "     " + str(message_details.status_code) + "\n")
        soupped_message_details = BeautifulSoup(message_details.text, "html.parser")

        received_time = re.search(r'Received Time:(.*)MID:', soupped_message_details.text, re.DOTALL)
        message_id = re.search(r'MID:(.*)Message Size:', soupped_message_details.text, re.DOTALL)
        message_size = re.search(r'Message Size:(.*)Subject:', soupped_message_details.text, re.DOTALL)
        message_subject = re.search(r'Subject:(.*)Envelope Sender:', soupped_message_details.text, re.DOTALL)
        envelope_sender = re.search(r'Envelope Sender:(.*)Envelope Recipients:', soupped_message_details.text, re.DOTALL)
        envelope_recipients = re.search(r'Envelope Recipients:(.*)Message ID Header:', soupped_message_details.text, re.DOTALL)
        message_id_header = re.search(r'Message ID Header:(.*)Cisco IronPort Host:', soupped_message_details.text, re.DOTALL)
        ironport_host = re.search(r'Cisco IronPort Host:(.*)SMTP Auth User ID:', soupped_message_details.text, re.DOTALL)
        snmp_auth_user_id = re.search(r'SMTP Auth User ID:(.*)Attachments:', soupped_message_details.text, re.DOTALL)
        attachments = re.search(r'Attachments:(.*)Sending Host Summary', soupped_message_details.text, re.DOTALL)

        try:
            write_string = "".join("#####" +
                                   received_time.group(1).replace("    ", "").replace("\n", "") + "#####" +
                                   message_id.group(1).replace("    ", "").replace("\n", "") + "#####" +
                                   message_size.group(1).replace("    ", "").replace("\n", "") + "#####" +
                                   message_subject.group(1).replace("    ", "").replace("\n", "") + "#####" +
                                   envelope_sender.group(1).replace("    ", "").replace("\n", "") + "#####" +
                                   envelope_recipients.group(1).replace("    ", "").replace("\n", "") + "#####" +
                                   message_id_header.group(1).replace("    ", "").replace("\n", "") + "#####" +
                                   ironport_host.group(1).replace("    ", "").replace("\n", "") + "#####" +
                                   snmp_auth_user_id.group(1).replace("    ", "").replace("\n", "") + "#####" +
                                   attachments.group(1).replace("    ", "").replace("\n", "")
                                   )
        except:
            print("################### PANIC PANIC PACNIC####################")
            print("################### PANIC PANIC PACNIC####################")
            print("################### PANIC PANIC PACNIC####################")
            output_log.write(
                str(datetime.now()) + "     " + "################### PANIC PANIC PACNIC####################" + "\n")
            output_log.write(
                str(datetime.now()) + "     " + "################### PANIC PANIC PACNIC####################" + "\n")
            output_log.write(
                str(datetime.now()) + "     " + "################### PANIC PANIC PACNIC####################" + "\n")
            output_log.write(
                str(datetime.now()) + "     " + "################### SOEMTHING BAD HAPPEND DURING PARSING ####################" + "\n")
            output_log.write(
                str(datetime.now()) + "     " + str(message_details.status_code) + "\n")
            output_log.write(
                str(datetime.now()) + "     " + str(message_details.text) + "\n")
            output_log.write(
                str(datetime.now()) + "     " + str(soupped_message_details.text) + "\n")
            output_log.write(
                str(datetime.now()) + "     " + "######### THIS ONE FAILED ##########" + message_details_url + "\n")
            output_log.write(
                str(datetime.now()) + "     " + "######### THIS ONE FAILED ##########" + message_details_url + "\n")
            output_log.write(
                str(datetime.now()) + "     " + "######### THIS ONE FAILED ##########" + message_details_url + "\n")
            output_log.write(
                str(datetime.now()) + "     " + "######### THIS ONE FAILED ##########" + message_details_url + "\n")
            output_log.write(
                str(datetime.now()) + "     " + "######### THIS ONE FAILED ##########" + message_details_url + "\n")
            try:
                print("session timed out (maybe) trying to log back in")
                output_log.write(str(datetime.now()) + "     " + "session timed out (maybe) trying to log back in" + "\n")
                if "User Session is not valid." in str(soupped_message_details.text):
                    print("found User Session is not valid. in text")
                    output_log.write(str(datetime.now()) + "     " + "found User Session is not valid. in text" + "\n")
                    esa_session.close()
                    print("killed old session")
                    output_log.write(str(datetime.now()) + "     " + "killed old session" + "\n")
                    check_access_to_esa()
                    print("access checked")
                    output_log.write(str(datetime.now()) + "     " + "access checked" + "\n")
                    login_to_esa()
                    print("loged in ok (I THINK)")
                    output_log.write(str(datetime.now()) + "     " + "loged in ok (I THINK)" + "\n")
                elif "process of restarting" in str(soupped_message_details.text):
                    print("process of restarting in text")
                    output_log.write(
                        str(datetime.now()) + "     " + "found process of restarting in text" + "\n")
                    time.sleep(300)
                    esa_session.close()
                    print("killed old session")
                    output_log.write(str(datetime.now()) + "     " + "killed old session" + "\n")
                    check_access_to_esa()
                    print("access checked")
                    output_log.write(str(datetime.now()) + "     " + "access checked" + "\n")
                    login_to_esa()
                    print("loged in ok (I THINK)")
                    output_log.write(str(datetime.now()) + "     " + "loged in ok (I THINK)" + "\n")
                elif "Application Error" in str(soupped_message_details.text):
                    print("Application Error in text")
                    output_log.write(
                        str(datetime.now()) + "     " + "found Application Error in text" + "\n")
                    time.sleep(300)
                    esa_session.close()
                    print("killed old session")
                    output_log.write(str(datetime.now()) + "     " + "killed old session" + "\n")
                    check_access_to_esa()
                    print("access checked")
                    output_log.write(str(datetime.now()) + "     " + "access checked" + "\n")
                    login_to_esa()
                    print("loged in ok (I THINK)")
                    output_log.write(str(datetime.now()) + "     " + "loged in ok (I THINK)" + "\n")
                else:
                    print("""couldnt find "User Session is not valid." OR "process of restarting" OR "process of 
                    restarting" in string to handle""")
                    output_log.write(str(datetime.now()) + "     " + """couldnt find "User Session is not valid." 
                    OR "process of restarting" OR "process of restarting" in string to handle""" + "\n")
            except:
                print("something else bad happened didnt find string in text")
                output_log.write(str(datetime.now()) + "     " + "something else bad happened didnt find string in text" + "\n")
            continue

        print(write_string)
        print("Working or URL " + str(working_url_counter) + "of" + str(len(detail_url_hunter_array_raw)))
        output_file.write(str(datetime.now()) + "     " + write_string + "\n")
        output_log.write(str(datetime.now()) + "     " + write_string + "\n")
        output_file.flush()
        output_log.flush()
        working_url_counter += 1


def create_output_file():
    try:
        output_filename = str(datetime.now()) + "-IronPortESAInterrogationTool-OUTPUTANSWERS"
        output_file_local = open(str(output_filename) + ".text", 'a+')
        output_log.write(str(datetime.now()) + "     " + "output file created sucessfully file name should be " +
                         str(output_filename) + "\n")
    except:
        print("something went bad opening/creating file for writing")
        print("Unexpected error:", sys.exc_info()[0])
        quit()
    return output_file_local


args = parse_input_arguments()
print("arguments parsed")
output_log = create_logfile()
print("logfile done")
proxy_server_to_use = set_proxy_if_needed()
csrf_key_origional = ""
esa_session = check_access_to_esa()
print("access checked NO proxy")
login_to_esa()

detail_url_hunter_array_raw = []
collect_message_url()
output_file = create_output_file()

collect_message_details_and_parse()

output_file.write(str(datetime.now()) + "     " + "ALL DONE GOING HOME - YOU OWE ME A BEER" + "\n")
output_log.write(str(datetime.now()) + "     " + "ALL DONE GOING HOME - YOU OWE ME A BEER" + "\n")

output_file.close()
output_log.close()
quit()
