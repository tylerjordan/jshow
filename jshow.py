# Author: Tyler Jordan
# File: jshow.py
# Description: The purpose of this script is to execute commands on multiple Juniper devices. The script works in
# Windows, Linux, and Mac enviroments. This script can do bulk configuration pushes by using a CSV. When using the
# template feature, it is possible to push unique configurations to devices.
#   - execute operational commands on one or more Juniper devices
#   - execute edit commands on one or more Juniper devices
#   - execute a dynamic template on one or more Juniper devices
#   - upgrade one or more Juniper devices

import platform
import subprocess
import getopt
import csv
import logging
import datetime
import pprint
import netaddr
import re

from jnpr.junos import Device
from jnpr.junos.utils.sw import SW
from jnpr.junos.exception import *
from ncclient.operations.errors import TimeoutExpiredError
from utility import *
from os.path import join
from getpass import getpass
from prettytable import PrettyTable
from Spinner import *
from sys import stdout
from lxml import etree

# Global Variables
credsCSV = ""
username = ""
password = ""
ssh_port = 22

iplist_dir = ""
log_dir = ""
config_dir = ""
csv_dir = ""
upgrade_dir = ""
images_dir = ""

system_slash = "/"   # This is the linux/mac slash format, windows format will be used in that case

remote_path = "/var/tmp"

ex_version_list = ['10.0', '10.1', '10.2', '10.3', '10.4', '11.1', '11.2', '11.3', '11.4', '12.1', '12.2', '12.3',
                   '13.1', '13.2', '13.2X50', '13.2X51', '13.2X52', '13.3', '14.1', '14.1X53', '14.2', '15.1',
                   '15.1X53', '16.1', '17.1', '17.2', '17.3']

# Function to determine running enviornment (Windows/Linux/Mac) and use correct path syntax
def detect_env():
    """ Purpose: Detect OS and create appropriate path variables. """
    global credsCSV
    global iplist_dir
    global config_dir
    global log_dir
    global csv_dir
    global upgrade_dir
    global images_dir
    global system_slash
    global ssh_port
    global dir_path
    global temp_conf
    global username
    global password

    dir_path = os.path.dirname(os.path.abspath(__file__))
    if platform.system().lower() == "windows":
        #print "Environment Windows!"
        iplist_dir = ".\\iplists\\"
        config_dir = ".\\configs\\"
        log_dir = ".\\logs\\"
        csv_dir = ".\\csv\\"
        upgrade_dir = ".\\upgrade\\"
        images_dir = ".\\images\\"
        system_slash = "\\"
    else:
        #print "Environment Linux/MAC!"
        iplist_dir = "./iplists/"
        config_dir = "./configs/"
        log_dir = "./logs/"
        csv_dir = "./csv/"
        upgrade_dir = "./upgrade/"
        images_dir = "./images/"

    credsCSV = os.path.join(dir_path, "pass.csv")
    temp_conf = os.path.join(dir_path, config_dir, "temp.conf")

# Handles arguments provided at the command line
def getargs(argv):
    # Interprets and handles the command line arguments
    try:
        opts, args = getopt.getopt(argv, "hu:", ["user="])
    except getopt.GetoptError:
        print("jscan.py -u <username>")
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print("jscan.py -u <username>")
            sys.exit()
        elif opt in ("-u", "--user"):
            return arg

# A function to open a connection to devices and capture any exceptions
def connect(ip):
    """ Purpose: Attempt to connect to the device

    :param ip:          -   IP of the device
    :param indbase:     -   Boolean if this device is in the database or not, defaults to False if not specified
    :return dev:        -   Returns the device handle if its successfully opened.
    """
    dev = Device(host=ip, user=username, password=password, auto_probe=True)
    # Try to open a connection to the device
    try:
        dev.open()
    # If there is an error when opening the connection, display error and exit upgrade process
    except ConnectRefusedError as err:
        message = "Host Reachable, but NETCONF not configured."
        stdout.write("Connect Fail - " + message + " |")
        return False
    except ConnectAuthError as err:
        message = "Unable to connect with credentials. User:" + username
        stdout.write("Connect Fail - " + message + " |")
        return False
    except ConnectTimeoutError as err:
        message = "Timeout error, possible IP reachability issues."
        stdout.write("Connect Fail - " + message + " |")
        return False
    except ProbeError as err:
        message = "Probe timeout, possible IP reachability issues."
        stdout.write("Connect Fail - " + message + " |")
        return False
    except ConnectError as err:
        message = "Unknown connection issue."
        stdout.write("Connect Fail - " + message + " |")
        return False
    except Exception as err:
        message = "Undefined exception."
        stdout.write("Connect Fail - " + message + " |")
        return False
    # If try arguments succeeded...
    else:
        return dev

# Function for running operational commands to multiple devices
def oper_commands(my_ips):
    print "*" * 50 + "\n" + " " * 10 + "OPERATIONAL COMMANDS\n" + "*" * 50
    # Provide selection for sending a single command or multiple commands from a file
    if not my_ips:
        my_ips = chooseDevices(iplist_dir)

    if my_ips:
        command_list = []
        print "\n" + "*" * 110 + "\n"
        command_list = getMultiInputAnswer("Enter a command to run")

        if getTFAnswer("Continue with operational requests?"):
            output_log = create_timestamped_log("oper_output_", "log")
            err_log = create_timestamped_log("oper_err_", "log")
            # Header of operational command output
            screen_and_log(starHeading("OPERATIONAL COMMANDS OUTPUT", 110), output_log)
            screen_and_log(('User: {0}\n').format(username), output_log)
            screen_and_log(('Performed: {0}\n').format(get_now_time()), output_log)
            screen_and_log(('Output Log: {0}\n').format(output_log), output_log)
            screen_and_log(('Error Log: {0}\n').format(err_log), output_log)
            screen_and_log(starHeading("COMMANDS EXECUTED", 110), output_log)
            for command in command_list:
                screen_and_log(' -> {0}\n'.format(command), output_log)
            screen_and_log('*' * 110 + '\n', output_log)

            # Loop over commands and devices
            devs_unreachable = []
            devs_no_output = []
            devs_with_output = []
            loop = 0
            try:
                screen_and_log("-" * 110 + "\n", output_log)
                for ip in my_ips:
                    command_output = ""
                    loop += 1
                    stdout.write("-> Connecting to " + ip + " ... ")
                    dev = connect(ip)
                    if dev:
                        print "Connected!"
                        hostname = dev.facts['hostname']
                        if not hostname:
                            hostname = "Unknown"
                        got_output = False
                        # Loop over the commands provided
                        if command_list:
                            stdout.write(hostname + ": Executing commands ")
                            for command in command_list:
                                command_output += "\n" + hostname + ": Executing -> {0}\n".format(command)
                                #com = dev.cli_to_rpc_string(command)
                                #print "Command: {0}\nRPC: {1}\n".format(command, com)
                                #if com is None:
                                try:
                                    results = dev.cli(command, warning=False)
                                except Exception as err:
                                    stdout.write("\n")
                                    screen_and_log("{0}: Error executing '{1}'. ERROR: {2}\n".format(ip, command, err), err_log)
                                    stdout.write("\n")
                                else:
                                    if results:
                                        command_output += results
                                        got_output = True
                                    stdout.write(".")
                                    stdout.flush()
                            if got_output:
                                devs_with_output.append(ip)
                                screen_and_log(command_output, output_log)
                                stdout.write("\n")
                            else:
                                devs_no_output.append(ip)
                                stdout.write(" No Output!\n")
                        # If no commands are provided, run the get_chassis_inventory on devices
                        else:
                            get_chassis_inventory(dev, hostname)
                        # Close connection to device
                        try:
                            dev.close()
                        except TimeoutExpiredError as err:
                            print "Error: {0}".format(err)
                            break
                    else:
                        screen_and_log("{0}: Unable to connect\n".format(ip), err_log)
                        devs_unreachable.append(ip)
                screen_and_log("-" * 110 + "\n", output_log)
                screen_and_log(starHeading("COMMANDS COMPLETED", 110), output_log)
                # Results of commands
                screen_and_log(starHeading("PROCESS SUMMARY", 110), output_log)
                screen_and_log("Devices With Output:  {0}\n".format(len(devs_with_output)), output_log)
                screen_and_log("Devices No Output:    {0}\n".format(len(devs_no_output)), output_log)
                screen_and_log("Devices Unreachable:  {0}\n".format(len(devs_unreachable)), output_log)
                screen_and_log("Total Devices:        {0}\n".format(len(my_ips)), output_log)
                screen_and_log("*" * 110 + "\n", output_log)
            except KeyboardInterrupt:
                print "Exiting Procedure..."
        else:
            print "\n!!! Configuration deployment aborted... No changes made !!!\n"
    else:
        print "\n!! Configuration deployment aborted... No IPs defined !!!\n"

# Grabs the devices chassis hardware info and places it in
def get_chassis_inventory(dev, hostname):
    # Testing context
    root = dev.rpc.get_chassis_inventory()
    print "\t- Gathering chassis hardware information..."
    inventory_listdict = []

    # Check to see if chassis exists
    if root.findtext('chassis'):
        # Gather chassis attribs
        for base in root.findall('chassis'):
            item = collect_attribs(base, hostname)
            if item:
                inventory_listdict.append(item)
            # Gather module attribs
            if base.findtext('chassis-module'):
                for module in base.findall('chassis-module'):
                    item = collect_attribs(module, hostname)
                    if item:
                        inventory_listdict.append(item)
                    # Gather attribs
                    if module.findtext('chassis-sub-module'):
                        for submodule in module.findall('chassis-sub-module'):
                            item = collect_attribs(submodule, hostname)
                            if item:
                                inventory_listdict.append(item)
                            # Gather attribs
                            if submodule.findtext('chassis-sub-sub-module'):
                                for subsubmodule in submodule.findall('chassis-sub-sub-module'):
                                    item = collect_attribs(subsubmodule, hostname)
                                    if item:
                                        inventory_listdict.append(item)
                                    # Gather attribs
                                    if subsubmodule.findtext('chassis-sub-sub-sub-module'):
                                        for subsubsubmodule in subsubmodule.findall('chassis-sub-sub-sub-module'):
                                            item = collect_attribs(subsubsubmodule, hostname)
                                            if item:
                                                inventory_listdict.append(item)
    # Add the content to the inventory CSV
    print "\t- Adding to CSV..."
    item_key = ['hostname', 'name', 'description', 'version', 'location', 'part-number', 'serial-number']
    inv_csv = os.path.join(csv_dir, "inventory.csv")
    listDictCSV(inventory_listdict, inv_csv, item_key)

# Collects the attributes from the object and returns a dictionary
def collect_attribs(dev_obj, hostname):
    item_dict = {'hostname': '', 'name': '', 'description': '', 'version': '', 'location': '',
                 'part-number': '', 'serial-number': ''}
    items = ['name', 'description', 'version', 'part-number', 'serial-number']

    location = "LOCATION"
    # Gather chassis attribs
    item_dict['hostname'] = hostname
    item_dict['location'] = location
    for item in items:
        if dev_obj.findtext(item):
            if item == 'name' and dev_obj.findtext(item) == 'CPU':
                return False
            else:
                item_dict[item] = dev_obj.findtext(item).replace(',', '')

    return item_dict

# Adds device specific content to a template file
def populate_template(template_file):
    command_list = txt_to_list(template_file)
    new_command_list = []
    if command_list:
        # Loop over commands
        for command in command_list:
            print("Command: {0}").format(command)
            # Check if this is an empty line, if it is, skip it
            if not re.match(r'^\s*$', command) or re.match(r'^#.*$', command):
                # If this line contains a variable...
                if re.match(r'.*\{\{.*\}\}.*', command):
                    print("Template Command: {0}").format(command)
                    matches = re.findall(r"\{\{.*?\}\}", command)
                    print("Template Matches: {0}").format(matches)
                    for match in matches:
                        term = match[3:-3]
                        vareg = r"{{ " + term + " }}"
                        print "Term: ".format(term)
                        print "Var regex: {0}".format(vareg)
                        command = re.sub(vareg, record[term], command)
                        exit()
                        #print "New String: {0}".format(command)
                # If this line doesn't contain a variable, use it as is
                else:
                    #print("Standard Command: {0}").format(command)
                    new_command_list.append(command)
    # Convert list to a file
    try:
        commands_file = list_to_txt(temp_conf, new_command_list)
    except Exception as err:
        print "ERROR Converting List to a File: {0}".format(err)
        return False
    else:
        return temp_conf

# Function actually pushing the commands to a device
def push_commands(commands_fp, output_log, ip):
    dev_dict = {'IP': ip, 'HOSTNAME': 'Unknown', 'MODEL': 'Unknown', 'JUNOS': 'Unknown', 'CONNECTED': 'No',
                'LOAD_SUCCESS': 'No', 'ERROR': 'No', 'devs_accessed': False, 'devs_successful': False,
                'devs_unreachable': False, 'devs_unsuccessful': False}
    dev = connect(ip)
    if dev:
        dev_dict['devs_accessed'] = ip
        dev_dict['CONNECTED'] = 'Yes'
        screen_and_log("Connected!\n", output_log)
        # Get the hostname
        hostname = dev.facts['hostname']
        if not hostname:
            hostname = "Unknown"
        dev_dict['HOSTNAME'] = hostname
        # Get the model number
        dev_dict['MODEL'] = dev.facts['model']
        # Get the version
        dev_dict['JUNOS'] = dev.facts['version']
        # Try to load the changes
        results = load_with_pyez(commands_fp, output_log, ip, hostname, username, password)
        if results == "Completed":
            dev_dict['devs_successful'] = ip
            dev_dict['LOAD_SUCCESS'] = 'Yes'
        else:
            screen_and_log("Moving to next device...\n", output_log)
            dev_dict['devs_unsuccessful'] = ip
            dev_dict['LOAD_SUCCESS'] = 'No'
            # Add brief error to CSV
            brief_error = results.split(" - ERROR")[0]
            dev_dict['ERROR'] = brief_error
    else:
        screen_and_log("Unable to Connect!\n", output_log)
        screen_and_log("{0}: Unable to connect\n".format(ip), output_log)
        dev_dict['devs_unreachable'] = ip
        dev_dict['CONNECTED'] = 'No'

    return dev_dict

# Function to push set commands to multiple devices
def standard_commands(my_ips):
    print "*" * 50 + "\n" + " " * 10 + "SET COMMANDS\n" + "*" * 50
    # Provide option for using a file to supply configuration commands
    if not my_ips:
        my_ips = chooseDevices(iplist_dir)
    if my_ips:
        set_file = ""
        commands_fp = ""
        command_list = []
        if not getTFAnswer('\nProvide commands from a file'):
            command_list = getMultiInputAnswer("Enter a set command")
            if list_to_txt(temp_conf, command_list):
                commands_fp = temp_conf
        else:
            filelist = getFileList(config_dir)
            # If the files exist...
            if filelist:
                set_config = getOptionAnswer("Choose a config file", filelist)
                commands_fp = config_dir + set_config
                command_list = txt_to_list(commands_fp)

        # Print the set commands that will be pushed
        print "\n" + " " * 10 + "Set Commands Entered"
        print "-" * 50
        if command_list:
            for one_comm in command_list:
                print " -> {0}".format(one_comm)
        print "-" * 50 + "\n"

        # Verify that user wants to continue with this deployment
        if getTFAnswer("Continue with set commands deployment?"):
            # ---------- STARTING LOGGING ------------
            # Start Logging and other stuff
            now = datetime.datetime.now()
            output_log = create_timestamped_log("set_output_", "log")
            summary_csv = create_timestamped_log("summary_csv_", "csv")

            # Print output header, for both screen and log outputs
            screen_and_log(starHeading("DEPLOY COMMANDS LOG", 110), output_log)
            screen_and_log(('User: {0}\n').format(username), output_log)
            screen_and_log(('Performed: {0}\n').format(get_now_time()), output_log)
            screen_and_log(('Output Log: {0}\n').format(output_log), output_log)

            # Print the commands that will be executed
            screen_and_log(starHeading("COMMANDS TO EXECUTE", 110), output_log)
            for line in command_list:
                screen_and_log(" -> {0}\n".format(line), output_log)
            screen_and_log("*" * 110 + "\n\n", output_log)

            # Define the attributes and show the start of the process
            screen_and_log(starHeading("START PROCESS", 110), output_log)

            # ---------- MAIN EXECUTION ----------
            # Deploy commands to list of ips
            results = deploy_config(commands_fp, command_list, my_ips)

            # ---------- ENDING LOGGING -----------
            # Display the end of the process
            screen_and_log(starHeading("END PROCESS", 110), output_log)

            # Results of commands
            screen_and_log(starHeading("PROCESS SUMMARY", 110), output_log)
            screen_and_log("Devices Accessed:       {0}\n".format(len(results['devs_accessed'])), output_log)
            screen_and_log("Devices Successful:     {0}\n".format(len(results['devs_successful'])), output_log)
            screen_and_log("Devices Unreachable:    {0}\n".format(len(results['devs_unreachable'])), output_log)
            screen_and_log("Devices Unsuccessful:   {0}\n".format(len(results['devs_unsuccessful'])), output_log)
            screen_and_log("Total Devices:          {0}\n\n".format(len(my_ips)), output_log)
            screen_and_log(starHeading("", 110), output_log)
        else:
            print "\n!!! Configuration deployment aborted... No changes made !!!\n"

# Function for capturing output and initiaing push function
def deploy_config(commands_fp, my_ips, output_log):
    # Lists
    devs_accessed = []
    devs_successful = []
    devs_unreachable = []
    devs_unsuccessful = []
    dict_of_lists = {'devs_accessed': [], 'devs_successful': [], 'devs_unreachable': [],
                     'devs_unsuccessful': []}

    # Loop over all devices in my_ips list
    loop = 0
    for ip in my_ips:
        loop += 1
        stdout.write("[{0} of {1}] - Connecting to {2} ... ".format(loop, len(my_ips), ip))
        results = push_commands(commands_fp, output_log, ip)
        screen_and_log("\n" + ("-" * 110) + "\n", output_log)
        if results['devs_accessed']: devs_accessed.append(ip)
        if results['devs_successful']: devs_successful.append(ip)
        if results['devs_unreachable']: devs_unreachable.append(ip)
        if results['devs_unsuccessful']: devs_unsuccessful.append(ip)

        # Print to a CSV file
        keys = ['HOSTNAME', 'IP', 'MODEL', 'JUNOS', 'CONNECTED', 'LOAD_SUCCESS', 'ERROR']
        dictCSV(results, summary_csv, keys)

    # Populate dict with lists
    dict_of_lists['devs_accessed'] = devs_accessed
    dict_of_lists['devs_successful'] = devs_successful
    dict_of_lists['devs_unreachable'] = devs_unreachable
    dict_of_lists['devs_unsuccessful'] = devs_unsuccessful

    return dict_of_lists

# Template function for bulk set command deployment
def template_commands():
    print "*" * 50 + "\n" + " " * 10 + "TEMPLATE COMMANDS\n" + "*" * 50

    # Choose the template configuration file to use
    filelist = getFileList(config_dir, 'txt')
    template_config = getOptionAnswer("Choose a template command (.txt) file", filelist)
    if template_config:
        template_file = config_dir + template_config
        print "-" * 50
        print " " * 10 + "File: " + template_config
        print "-" * 50
        # Display the commands in the configuration file
        for line in txt_to_list(template_file):
            print " -> {0}".format(line)
        print "-" * 50
    else:
        print "Quit Template Menu..."
        return False

    # Choose the template csv file to use
    filelist = getFileList(csv_dir, 'csv')
    csv_config = getOptionAnswer("Choose a template csv (.csv) file", filelist)
    if csv_config:
        csv_file = csv_dir + csv_config
        list_dict = csvListDict(csv_file)
        print "-" * 50
        print " " * 10 + "File: " + csv_config
        print "-" * 50

        # Capture the headers of the CSV file
        with open(csv_file, 'r') as f:
            first_line = f.readline().strip()
        keys = first_line.split(',')

        # Sort headers with mgmt_ip being the first key
        sorted_keys = []
        if 'mgmt_ip' in keys:
            sorted_keys.append('mgmt_ip')
            for one_key in keys:
                if one_key != 'mgmt_ip':
                    sorted_keys.append(one_key)
            # Print the CSV file and the
            for device in list_dict:
                for key in sorted_keys:
                    if key == 'mgmt_ip':
                        print " -> {0}".format(device[key])
                    else:
                        print " ---> {0}: {1}".format(key, device[key])
            print "-" * 50
            print "Total IPs: {0}".format(len(list_dict))

            if getTFAnswer("Continue with template deployment?"):
                # ---------- STARTING LOGGING ------------
                # Start Logging and other stuff
                now = datetime.datetime.now()
                output_log = create_timestamped_log("set_output_", "log")
                summary_csv = create_timestamped_log("summary_csv_", "csv")

                # Print output header, for both screen and log outputs
                screen_and_log(starHeading("DEPLOY COMMANDS LOG", 110), output_log)
                screen_and_log(('User: {0}\n').format(username), output_log)
                screen_and_log(('Performed: {0}\n').format(get_now_time()), output_log)
                screen_and_log(('Output Log: {0}\n').format(output_log), output_log)

                # Print the unpopulated template file to be used to create the configs
                screen_and_log(starHeading("COMMANDS TO EXECUTE", 110), output_log)
                command_list = txt_to_list(template_file)
                for line in command_list:
                    screen_and_log(" -> {0}\n".format(line), output_log)
                screen_and_log("*" * 110 + "\n\n", output_log)

                # Define the attributes and show the start of the process
                screen_and_log(starHeading("START PROCESS", 110), output_log)

                # Deploy commands to list of ips
                results = deploy_template_config(template_file, list_dict, output_log, summary_csv)

                # Display the end of the process
                screen_and_log(starHeading("END PROCESS", 110), output_log)

                # Results of commands
                screen_and_log(starHeading("PROCESS SUMMARY", 110), output_log)
                screen_and_log("Devices Accessed:       {0}\n".format(len(results['devs_accessed'])), output_log)
                screen_and_log("Devices Successful:     {0}\n".format(len(results['devs_successful'])), output_log)
                screen_and_log("Devices Unreachable:    {0}\n".format(len(results['devs_unreachable'])), output_log)
                screen_and_log("Devices Unsuccessful:   {0}\n".format(len(results['devs_unsuccessful'])), output_log)
                screen_and_log("Total Devices:          {0}\n\n".format(len(list_dict)), output_log)
                screen_and_log(starHeading("", 110), output_log)
                return True
            else:
                print "\n!!! Configuration deployment aborted... No changes made !!!\n"
                return False
        else:
            print "Unable to find mandatory 'mgmt_ip' column in {0}. Please check the column headers.".format(csv_file)
            return False
    else:
        print "Quit Template Menu..."
        return False

# Function for capturing output and initiaing push function
def deploy_template_config(template_file, list_dict, output_log, summary_csv):
    devs_accessed = []
    devs_successful = []
    devs_unreachable = []
    devs_unsuccessful = []
    dict_of_lists = {'devs_accessed': [], 'devs_successful': [], 'devs_unreachable': [], 'devs_unsuccessful': []}

    # Loop over all devices in list of dictionaries
    loop = 0
    for device in list_dict:
        loop += 1
        stdout.write("[{0} of {1}] - Connecting to {2}\n".format(loop, len(list_dict), device['mgmt_ip']))
        results = push_commands(populate_template(template_file), output_log, device['mgmt_ip'])
        screen_and_log("\n" + ("-" * 110) + "\n", output_log)
        if results['devs_accessed']: devs_accessed.append(device['mgmt_ip'])
        if results['devs_successful']: devs_successful.append(device['mgmt_ip'])
        if results['devs_unreachable']: devs_unreachable.append(device['mgmt_ip'])
        if results['devs_unsuccessful']: devs_unsuccessful.append(device['mgmt_ip'])

        # Print to a CSV file
        keys = ['HOSTNAME', 'IP', 'MODEL', 'JUNOS', 'CONNECTED', 'LOAD_SUCCESS', 'ERROR']
        dictCSV(results, summary_csv, keys)

    # Populate dict with lists
    dict_of_lists['devs_accessed'] = devs_accessed
    dict_of_lists['devs_successful'] = devs_successful
    dict_of_lists['devs_unreachable'] = devs_unreachable
    dict_of_lists['devs_unsuccessful'] = devs_unsuccessful

    return dict_of_lists

# Function to exit program
def quit():
    print("Thank you for using jShow!")
    sys.exit(0)

# Create a log
def create_timestamped_log(prefix, extension):
    now = datetime.datetime.now()
    return log_dir + prefix + now.strftime("%Y%m%d-%H%M") + "." + extension

# Create an upgrade dictionary
def upgrade_menu():
    intial_upgrade_ld = []
    heading_list = ['Hostname', 'IP', 'Model', 'Current Code', 'Target Code']
    key_list = ['hostname', 'ip', 'model', 'curr_code', 'targ_code']

    # Ask user how to select devices for upgrade (file or manually)
    my_options = ['Add from a CSV file', 'Add from a list of IPs', 'Add IPs Individually', 'Continue', 'Quit']
    print "*" * 50 + "\n" + " " * 10 + "JSHOW: UPGRADE JUNIPERS\n" + "*" * 50
    while True:
        answer = getOptionAnswerIndex('Make a Selection', my_options)
        print subHeading("ADD CANDIDATES", 10)
        # Option for providing a file with IPs and target versions
        if answer == "1":
            selected_file = getOptionAnswer("Choose a CSV file", getFileList(upgrade_dir, 'csv'))
            temp_ld = csvListDict(selected_file, keys=['ip', 'target_code'])
            # Loop over all CSV entries
            print "*" * 50
            if selected_file:
                for chassis in temp_ld:
                    ip = chassis['ip']
                    targ_code = chassis['target_code']
                    # Checks if the IP already exists, if it doesn't, add it
                    if not any(d['ip'] == ip for d in intial_upgrade_ld):
                        chassis_info = get_chassis_info(ip, targ_code=None)
                        # Check if we are able to capture chassis info,
                        if chassis_info:
                            intial_upgrade_ld.append(chassis_info)
                        else:
                            print "Skipping..."
                    else:
                        print "IP {0} is already in the list. Skipping...".format(ip)
                print "*" * 50
                print ""
                print subHeading("CANDIDATE LIST", 10)
                print_listdict(intial_upgrade_ld, heading_list, key_list)
        # Option for creating a listDict from a source file with IPs
        elif answer == "2":
            ip_list = []
            # Lets user select an "ips" file from a directory
            selected_file = getOptionAnswer("Choose a IPS file", getFileList(upgrade_dir, 'ips'))
            # Convert it to a list and then add them to a list dictionary
            ip_list = txt_to_list(selected_file)
            # Loop over all the IPs in the list
            print "*" * 50
            if selected_file:
                for ip in ip_list:
                    # Checks if the IP already exists, if it doesn't, add it
                    if not any(d['ip'] == ip for d in intial_upgrade_ld):
                        chassis_info = get_chassis_info(ip, targ_code=None)
                        # Check if we are able to capture chassis info,
                        if chassis_info:
                            intial_upgrade_ld.append(chassis_info)
                        else:
                            print "Skipping..."
                    else:
                        print "IP {0} is already in the list. Skipping...".format(ip)
                print "*" * 50
                print ""
                print subHeading("CANDIDATE LIST", 10)
                print_listdict(intial_upgrade_ld, heading_list, key_list)
        # Option for manually providing the information
        elif answer == "3":
            ip_list = []
            # Ask for an IP address
            while True:
                ip = getInputAnswer(question="Enter an IPv4 Host Address('q' when done)")
                if ip == "q":
                    break
                # Check if answer is a valid IPv4 address
                elif netaddr.valid_ipv4(ip):
                    # Checks if the IP already exists, if it doesn't, add it
                    if not any(d['ip'] == ip for d in intial_upgrade_ld):
                        print "*" * 50
                        chassis_info = get_chassis_info(ip, targ_code=None)
                        # Check if we are able to capture chassis info,
                        if chassis_info:
                            intial_upgrade_ld.append(chassis_info)
                        else:
                            print "Skipping..."
                        print "*" * 50
                    else:
                        print "IP {0} is already in the list. Skipping...".format(ip)
            print ""
            print subHeading("CANDIDATE LIST", 10)
            print_listdict(intial_upgrade_ld, heading_list, key_list)
        # Finish selection and continue
        elif answer == "4" and intial_upgrade_ld:
            final_upgrade_ld = format_data(intial_upgrade_ld)
            # Display the list of target codes chosen
            print ""
            print subHeading("UPGRADE LIST", 40)
            print_listdict(final_upgrade_ld, heading_list, key_list)
            # Start upgrade process
            upgrade_loop(final_upgrade_ld)
            break
        # Quit this menu
        elif answer == "5":
            break
    print "Exiting JSHOW: UPGRADE JUNIPERS"

# Function to loop over all devices chosen for upgrades
def upgrade_loop(upgrade_ld):
    # Get Reboot Preference
    reboot = "askReboot"
    myoptions = ['Reboot ALL devices AFTER upgrade', 'Do not reboot ANY device AFTER upgrade', 'Ask for ALL devices']
    answer = getOptionAnswerIndex("How would you like to handle reboots", myoptions)

    if answer == "1":
        reboot = "doReboot"
    elif answer == "2":
        reboot = "noReboot"
    else:
        reboot = "askReboot"

    print subHeading("UPGRADE LIST", 40)
    t = PrettyTable(['Hostname', 'IP', 'Model', 'Current Code', 'Target Code', 'Reboot'])
    for device in upgrade_ld:
        t.add_row([device['hostname'], device['ip'], device['model'], device['curr_code'], device['targ_code'], reboot])
    print t
    # Last confirmation before entering loop
    verified = getTFAnswer("Please Verify the information above. Continue")

    # Upgrade Loop
    # verified = 'y'
    if verified:
        # Create log file
        now = datetime.datetime.now()
        date_time = now.strftime("%Y-%m-%d-%H%M")
        install_log = log_dir + "install-log_" + date_time + ".log"
        host = "PyEZ Server"

        # Start logging if required
        logging.basicConfig(filename=install_log, level=logging.INFO, format='%(asctime)s:%(name)s: %(message)s')
        logging.getLogger().name = host
        logging.getLogger().addHandler(logging.StreamHandler())
        logging.info('Information logged in {0}'.format(install_log))

        # Loop over all devices in list
        for device in upgrade_ld:
            # Define the Device being upgraded
            logging.info('-' * 30)
            logging.info('Upgrading {0} IP: {1}'.format(device['hostname'], device['ip']))
            logging.info('Model ........ {0}'.format(device['model']))
            logging.info('Current OS ... {0}'.format(device['curr_code']))
            logging.info('Target OS .... {0}'.format(device['targ_code']))
            logging.info('-' * 30)

            # Assemble image file path
            image_path_file = images_dir + device['targ_code']

            # Upgrade the device
            upgrade_device(device['ip'], image_path_file, logging, reboot)

        # Attempt to deactivate logging
        print "Attempt to deactivate logging..."
        logging.disable('CRITICAL')

# Upgrade the Juniper device
def upgrade_device(host, package, logging, reboot, remote_path='/var/tmp', validate=True):

    # Verify package is present
    if not (os.path.isfile(package)):
        msg = 'Software package does not exist: {0}. '.format(package)
        logging.error(msg)
        sys.exit()

    dev = Device(host=host, user=username, passwd=password)
    try:
        dev.open()
    except ConnectError as err:
        logging.error('Cannot connect to device: {0}\n'.format(err))
        return False

    # Create an instance of SW
    sw = SW(dev)

    try:
        logging.info('Starting the software upgrade process: {0}'.format(package))
        ok = sw.install(package=package, remote_path = remote_path, progress=update_progress, validate=validate)
    except Exception as err:
        logging.error('Unable to install software, {0}'.format(err))
        ok = False
        dev.close()
        logging.shutdown()
        return False

    if ok is True:
        logging.info('Software installation complete.')
        # Check rebooting status...
        if reboot == "askReboot":
            answer = getYNAnswer('Would you like to reboot')
            if answer == 'y':
                reboot = "doReboot"
            else:
                reboot = "noReboot"
        if reboot == "doReboot":
            rsp = sw.reboot()
            logging.info('Upgrade pending reboot cycle, please be patient.')
            logging.info(rsp)
            # Open a command terminal to monitor device connectivity
            # os.system("start cmd /c ping -t " + ip)
        elif reboot == "noReboot":
            logging.info('Reboot NOT performed. System must be rebooted to complete upgrade.')
    else:
        logging.error('Issue installing software')
        logging.shutdown()
        dev.close()
        return False

    # End the NDTCONF session and close the connection
    dev.close()
    return True

# Log the upgrade progress
def update_progress(dev, report):
    # Log the progress of the installation process
    logging.info(report)

# Capture chassis info
def get_chassis_info(ip, targ_code):
    chassis_dict = {}
    stdout.write("Connecting to {0} ... ".format(ip))
    dev = connect(ip)
    if dev:
        try:
            chassis_dict['ip'] = ip
            chassis_dict['targ_code'] = targ_code
            chassis_dict['curr_code'] = dev.facts['version']
            chassis_dict['model'] = dev.facts['model']
            chassis_dict['hostname'] = dev.facts['hostname']
        except Exception as err:
            print " Error detected: {0}".format(err)
        else:
            print " Information Successfully Collected!"
        dev.close()
    return chassis_dict

# Fix any deficiencies in the list dictionary. Verify a valid IP and valid code if the code is provided.
def format_data(intial_upgrade_ld):
    # List Dictionary to store completed list in
    final_upgrade_ld = []

    # Loop over all devices in the list
    for host_dict in intial_upgrade_ld:
        # Get target code and corresponding image file
        if host_dict['curr_code'] and host_dict['model']:
            print "Hostname.........{0}".format(host_dict['hostname'])
            print "IP...............{0}".format(host_dict['ip'])
            print "Model............{0}".format(host_dict['model'])
            print "Current Code.....{0}".format(host_dict['curr_code'])
            print "Requested Code...{0}".format(host_dict['targ_code'])

            target_code_file = get_target_image(host_dict['curr_code'], host_dict['targ_code'], host_dict['model'])
            if target_code_file:
                final_upgrade_ld.append({'hostname': host_dict['hostname'], 'ip': host_dict['ip'],
                                         'model': host_dict['model'], 'curr_code': host_dict['curr_code'],
                                         'targ_code': target_code_file})
                print "--> Selected version {0} for {1}".format(target_code_file, host_dict['ip'])
            else:
                pass
        else:
            print "--> ERROR: Unable to verify current code and model"

    return final_upgrade_ld

# Checks the code to make sure its available and that the code is correct for the model
def get_target_image(curr_code, targ_code, model):
    exact_match = []
    partial_match = []
    found_match = False

    # Extract model, type, and prefix
    dev_model = model[:4]
    dev_type = dev_model[:2].lower()
    dev_prefix = str(dev_model[-2:])

    # Loop over each available image in the images directory
    for img_file in getFileList(images_dir, "tgz"):
        # Remove the path prefix
        file_only = img_file.rsplit('/', 1)[1]
        # Regex to match the current device model number
        image_regex = r'^jinstall-' + re.escape(dev_type) + r'-' + re.escape(dev_prefix) + r'\d{2}-\d{2}\.\d{1}.*-domestic-signed\.tgz$'
        # If this image matches the device model...
        if re.search(image_regex, file_only):
            found_match = True
            # If a target code was specified for this upgrade...
            if targ_code:
                # Check if we can match the requested target code...
                if targ_code in file_only:
                    print " --> Found Exact Match: {0}".format(file_only)
                    exact_match.append(file_only)
                # If we can't match target code, return model matches
                else:
                    print " --> Found Partial Match: {0}".format(file_only)
                    partial_match.append(file_only)
            # If no target was prescribed, return model matches
            else:
                print " --> Found Partial Match: {0}".format(file_only)
                partial_match.append(file_only)
    #print "FINISHED WITH IMAGE CHECK!"

    # If a match was found...
    print ""
    if found_match:
        if exact_match:
            if len(exact_match) == 1:
                print "Exact Match!"
                return exact_match[0]
            else:
                print "Mutiple exact matches found!"
                return getOptionAnswer("Please choose an image", exact_match)
        else:
            print "Partial matches found!"
            return getOptionAnswer("Please choose an image", partial_match)
    else:
        print "No matches were found!"
        return getOptionAnswer("Please choose an image", partial_match)

    # If only one exact match exists, automatically add it as the target image
    # If multiple exact matches exist, only display exact maches for the user to choose from
    # If only partial matches exist, display them for the user to choose from
    # If no matches exist, display all images

        #else:
            #print "\t --> Didn't Match: {0}".format(file_only)

        #selected_file = getOptionAnswer("Choose an image file", getFileList(upgrade_dir, 'tgz'))

# Print a list dictionary using PrettyTable
def print_listdict(list_dict, headings, keys):
    """ 
        Purpose: Display a table showing contents of the list dictionary.
        Returns: Nothing
    """
    t = PrettyTable(headings)
    for host_dict in list_dict:
        # print device
        mylist = []
        for key in keys:
            if key in host_dict.keys():
                mylist.append(host_dict[key])
            else:
                mylist.append("")
        t.add_row(mylist)
    print t
    print "Total Items: {0}".format(len(list_dict))


# Main execution loop
if __name__ == "__main__":
    # Detect the platform type
    detect_env()

    # Get a username and password from the user
    username = getargs(sys.argv[1:])
    if not username:
        print 'Please supply a username as an argument: jshow.py -u <username>'
        exit()
    password = getpass(prompt="\nEnter your password: ")

    # Define menu options
    my_options = ['Execute Operational Commands', 'Execute Set Commands', 'Execute Template Commands', 'Upgrade Junipers', 'Quit']
    my_ips = []

    # Get menu selection
    while True:
        stdout.write("\n\n")
        print "*" * 50 + "\n" + " " * 10 + "JSHOW: MAIN MENU\n" + "*" * 50
        answer = getOptionAnswerIndex('Make a Selection', my_options)
        if answer == "1":
            oper_commands(my_ips)
        elif answer == "2":
            standard_commands(my_ips)
        elif answer == "3":
            template_commands()
        elif answer == "4":
            upgrade_menu()
        elif answer == "5":
            quit()
