# Author: Tyler Jordan
# File: jshow.py
# Last Modified: 2/2/2017
# Description: The purpose of this script is to execute commands on multiple Juniper devices. The script works in
# Windows, Linux, and Mac enviroments. This script can do bulk configuration pushes by using a CSV. When using the
# template feature, it is possible to push unique configurations to devices.
#   - execute operational commands on one or more Juniper devices
#   - execute edit commands on one or more Juniper devices
#   - execute a dynamic template on one or more Juniper devices

import platform
import subprocess
import getopt
import csv
import logging
import datetime
import pprint

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

credsCSV = ""
username = ""
password = ""
ssh_port = 22

iplist_dir = ""
log_dir = ""
config_dir = ""
csv_dir = ""

system_slash = "/"   # This is the linux/mac slash format, windows format will be used in that case

remote_path = "/var/tmp"

def detect_env():
    """ Purpose: Detect OS and create appropriate path variables. """
    global credsCSV
    global iplist_dir
    global config_dir
    global log_dir
    global csv_dir
    global system_slash
    global ssh_port
    global dir_path
    global temp_conf

    dir_path = os.path.dirname(os.path.abspath(__file__))
    if platform.system().lower() == "windows":
        #print "Environment Windows!"
        iplist_dir = ".\\iplists\\"
        config_dir = ".\\configs\\"
        log_dir = ".\\logs\\"
        csv_dir = ".\\csv\\"
        system_slash = "\\"
    else:
        #print "Environment Linux/MAC!"
        iplist_dir = "./iplists/"
        config_dir = "./configs/"
        log_dir = "./logs/"
        csv_dir = "./csv/"

    credsCSV = os.path.join(dir_path, "pass.csv")
    temp_conf = os.path.join(dir_path, config_dir, "temp.conf")

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

def connect(ip):
    """ Purpose: Attempt to connect to the device

    :param ip:          -   IP of the device
    :param indbase:     -   Boolean if this device is in the database or not, defaults to False if not specified
    :return dev:        -   Returns the device handle if its successfully opened.
    """
    dev = Device(host=ip, user=username, passwd=password, auto_probe=True)
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
                                #print "Command: {0}\nRPC: {1}\n".format(command, dev.cli_to_rpc_string(command))
                                #com = dev.cli_to_rpc_string(command)

                                try:
                                    results = dev.cli(command)
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
def populate_template(record, template_file):
    command_list = txt_to_list(template_file)
    new_command_list = []
    if command_list:
        # Loop over commands
        for command in command_list:
            #print("Command: {0}").format(command)
            if not re.match(r'^\s*$', command):
                if re.match(r'.*\{\{.*\}\}.*', command):
                    #print("Template Command: {0}").format(command)
                    matches = re.findall(r"\{\{.*?\}\}", command)
                    #print("Template Matches: {0}").format(matches)
                    for match in matches:
                        term = match[3:-3]
                        vareg = r"{{ " + term + " }}"
                        print "Term: ".format(term)
                        print "Var regex: {0}".format(vareg)
                        command = re.sub(vareg, record[term], command)
                        #print "New String: {0}".format(command)
                #else:
                    #print("Standard Command: {0}").format(command)
            new_command_list.append(command)
    return new_command_list

# Function actually pushing the commands to a device
def push_commands(commands_fp, output_log, ip):
    dev_dict = {'IP': ip, 'HOSTNAME': 'Unknown', 'MODEL': 'Unknown', 'JUNOS': 'Unknown', 'CONNECTED': 'No',
                'LOAD_SUCCESS': 'No', 'ERROR': 'None', 'devs_accessed': False, 'devs_successful': False,
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
            # Add extensive error to "error" log
            log_only(results, error_log)
    else:
        screen_and_log("Unable to Connect!\n", output_log)
        screen_and_log("{0}: Unable to connect\n".format(ip), output_log)
        dev_dict['devs_unreachable'] = ip
        dev_dict['CONNECTED'] = 'No'

    return dev_dict

# Function for capturing output and initiaing push function
def deploy_config(commands_fp, command_list, my_ips):
    now = datetime.datetime.now()
    output_log = create_timestamped_log("set_output_", "log")
    summary_csv = create_timestamped_log("summary_csv_", "csv")
    error_log = create_timestamped_log("error_details_", "log")

    # Print output header, for both screen and log outputs
    screen_and_log(starHeading("DEPLOY COMMANDS LOG", 110), output_log)
    screen_and_log(('User: {0}\n').format(username), output_log)
    screen_and_log(('Performed: {0}\n').format(get_now_time()), output_log)
    screen_and_log(('Output Log: {0}\n').format(output_log), output_log)
    screen_and_log(starHeading("COMMANDS TO EXECUTE", 110), output_log)
    for line in command_list:
        screen_and_log(" -> {0}\n".format(line), output_log)
    screen_and_log("*" * 110 + "\n\n", output_log)

    # Define the attributes and show the start of the process
    screen_and_log(starHeading("START PROCESS", 110), output_log)
    devs_accessed = []
    devs_successful = []
    devs_unreachable = []
    devs_unsuccessful = []

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

    # Display the end of the process
    screen_and_log(starHeading("END PROCESS", 110), output_log)

    # Results of commands
    screen_and_log(starHeading("PROCESS SUMMARY", 110), output_log)
    screen_and_log("Devices Accessed:       {0}\n".format(len(devs_accessed)), output_log)
    screen_and_log("Devices Successful:     {0}\n".format(len(devs_successful)), output_log)
    screen_and_log("Devices Unreachable:    {0}\n".format(len(devs_unreachable)), output_log)
    screen_and_log("Devices Unsuccessful:   {0}\n".format(len(devs_unsuccessful)), output_log)
    screen_and_log("Total Devices:          {0}\n\n".format(len(my_ips)), output_log)
    screen_and_log(starHeading("", 110), output_log)

# Template function for bulk set command deployment
def template_commands():
    print "*" * 50 + "\n" + " " * 10 + "TEMPLATE COMMANDS\n" + "*" * 50

    # Choose the template configuration file to use
    filelist = getFileList(config_dir)
    template_config = getOptionAnswer("Choose a template config file", filelist)
    template_file = config_dir + template_config
    print "-" * 50
    print " " * 10 + "File: " + template_config
    print "-" * 50
    # Display the commands in the configuration file
    for line in txt_to_list(template_file):
        print " -> {0}".format(line)
    print "-" * 50

    # Choose the template csv file to use
    filelist = getFileList(csv_dir)
    csv_config = getOptionAnswer("Choose a template csv file", filelist)
    csv_file = csv_dir + csv_config
    list_dict = csvListDict(csv_file)
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
            # Create log file for operation
            now = datetime.datetime.now()
            output_log = log_dir + "temp_cmd_" + now.strftime("%Y%m%d-%H%M") + ".log"
            print('\nInformation logged in {0}'.format(output_log))

            # Print output header, for both screen and log outputs
            screen_and_log("*" * 110 + "\n" + " " * 40 + "TEMPLATE COMMANDS OUTPUT\n" + "*" * 110 + "\n", output_log)
            screen_and_log(('User: {0}\n').format(username), output_log)
            screen_and_log(('Performed: {0}\n').format(now), output_log)
            screen_and_log('*' * 110 + '\n' + " " * 40 + "COMMANDS TO EXECUTE\n" + "*" * 110 + '\n', output_log)
            for line in txt_to_list(template_file):
                screen_and_log(" -> {0}\n".format(line), output_log)
            screen_and_log("*" * 110 + "\n\n", output_log)

            # Try to load configurations onto defined devices
            screen_and_log("-" * 49 + " START LOAD " + "-" * 49 + '\n', output_log)
            devs_accessed = 0
            devs_unreachable = 0
            loop = 0
            for record in list_dict:
                loop += 1
                ip = record['mgmt_ip']
                if ping(ip):
                    devs_accessed += 1
                    hostname = get_fact(ip, username, password, "hostname")
                    if not hostname:
                        hostname = "Unknown"
                    screen_and_log('*' * 110 + '\n', output_log)
                    screen_and_log(' ' * 30 + '[{0} at {1}]'.format(hostname, ip), output_log)
                    screen_and_log(' ({0} of {1})\n'.format(loop, len(list_dict)), output_log)
                    screen_and_log('*' * 110 + '\n', output_log)
                    screen_and_log("-" * 50 + " COMMANDS " + "-" * 50 + '\n', output_log)
                    try:
                        command_list = populate_template(record, template_file)
                        exit(0)
                    except Exception as err:
                        print "Issues with populating the template. ERROR: {0}".format(err)
                        break
                    for command in command_list:
                        screen_and_log((" -> {0}\n".format(command)), output_log)
                    screen_and_log("-" * 110 + '\n', output_log)
                    try:
                        screen_and_log("-" * 50 + " EXECUTE " + "-" * 51 + '\n\n', output_log)
                        set_command(ip, username, password, ssh_port, output_log, command_list)
                        screen_and_log("\n" + ("-" * 110) + '\n\n', output_log)
                    except Exception as err:
                        print "Problem changing configuration. ERROR: {0}".format(err)
                else:
                    devs_unreachable += 1
                    screen_and_log("-" * 110 + '\n', output_log)
                    screen_and_log("Unable to ping {0}, skipping. ({1} of {2})\n".format(ip, str(loop), len(list_dict)), output_log)
                    screen_and_log("-" * 110 + '\n\n', output_log)

            screen_and_log("-" * 50 + " END LOAD " + "-" * 50 + '\n\n', output_log)
            # Results of commands
            screen_and_log("*" * 32 + " Process Summary " + "*" * 31 + '\n\n', output_log)
            screen_and_log("Devices Accessed:    {0}\n".format(devs_accessed), output_log)
            screen_and_log("Devices Unreachable: {0}\n".format(devs_unreachable), output_log)
            screen_and_log("Total Devices:       {0}\n\n".format(loop), output_log)
            screen_and_log('*' * 80 + '\n\n', output_log)
        else:
            print "\n!!! Configuration deployment aborted... No changes made !!!\n"
    else:
        print "Unable to find mandatory 'mgmt_ip' column in {0}. Please check the column headers.".format(csv_file)


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
            # Deploy commands to list of ips
            deploy_config(commands_fp, command_list, my_ips)
        else:
            print "\n!!! Configuration deployment aborted... No changes made !!!\n"

# Function to exit program
def quit():
    print("Thank you for using jShow. Powered by electricity!")
    sys.exit(0)

# Create a log
def create_timestamped_log(prefix, extension):
    now = datetime.datetime.now()
    return log_dir + prefix + now.strftime("%Y%m%d-%H%M") + "." + extension

# Main execution loop
if __name__ == "__main__":
    # Detect the platform type
    detect_env()

    # Get a username and password from the user
    username = getargs(sys.argv[1:])
    password = getpass(prompt="\nEnter your password: ")

    # Define menu options
    my_options = ['Execute Operational Commands', 'Execute Set Commands', 'Execute Template Commands', 'Quit']
    my_ips = []

    # Get menu selection
    while True:
        stdout.write("\n\n")
        print "*" * 50 + "\n" + " " * 10 + "JSHOW MAIN MENU\n" + "*" * 50
        answer = getOptionAnswerIndex('Make a Selection', my_options)
        if answer == "1":
            oper_commands(my_ips)
        elif answer == "2":
            standard_commands(my_ips)
        elif answer == "3":
            template_commands()
        elif answer == "4":
            quit()
