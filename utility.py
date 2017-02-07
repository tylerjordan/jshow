# File: utility.py
# Author: Tyler Jordan
# Modified: 1/27/2017
# Purpose: Assist CBP engineers with Juniper configuration tasks

import sys, re, os, csv
import fileinput
import glob
import code
import paramiko  # https://github.com/paramiko/paramiko for -c -mc -put -get
import logging
import subprocess
import platform
import ipaddress

from os import listdir
from os.path import isfile, join, exists
from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from jnpr.junos.exception import ConnectError
from jnpr.junos.exception import LockError
from jnpr.junos.exception import UnlockError
from jnpr.junos.exception import ConfigLoadError
from jnpr.junos.exception import CommitError
from ncclient import manager  # https://github.com/ncclient/ncclient
from ncclient.transport import errors


# --------------------------------------
# ANSWER METHODS
#--------------------------------------
# Method for asking a question that has a single answer, returns answer
def getOptionAnswer(question, options):
    answer = ""
    loop = 0
    while not answer:
        print "\n" + question + ':\n'
        for option in options:
            loop += 1
            print '[' + str(loop) + '] -> ' + option
        answer = raw_input('\nYour Selection: ')
        print "*" * 50
        try:
            if int(answer) >= 1 and int(answer) <= loop:
                index = int(answer) - 1
                return options[index]
        except Exception as err:
            print "Invalid Entry - ERROR: {0}".format(err)
        else:
            print "Bad Selection"
        answer = ""
        loop = 0


# Method for asking a question that can have multiple answers, returns list of answers
def getOptionMultiAnswer(question, options):
    answer_str = ""
    loop = 0
    while not answer_str and options:
        print "\n" + question + ':\n'
        for option in options:
            loop += 1
            print '[' + str(loop) + '] -> ' + option
        answer_str = raw_input('\nYour Selections: ')
        print "*" * 50
        try:
            answer_list = []
            index_list = answer_str.split(",")
            for answer in index_list:
                index = int(answer) - 1
                answer_list.append(options[index])
            return answer_list
        except Exception as err:
            print "Invalid Entry - ERROR: {0}".format(err)
        else:
            print "Bad Selection"
        answer_str = ""
        loop = 0


# Method for asking a question that has a single answer, returns answer index
def getOptionAnswerIndex(question, options):
    answer = ""
    loop = 0
    while not answer:
        print "\n" + question + ':\n'
        for option in options:
            loop += 1
            print '[' + str(loop) + '] -> ' + option
        answer = raw_input('\nYour Selection: ')
        print "*" * 50
        try:
            if int(answer) >= 1 and int(answer) <= loop:
                return answer
        except Exception as err:
            print "Invalid Entry - ERROR: {0}".format(err)
        else:
            print "Bad Selection"
        answer = ""
        loop = 0


# Method for asking a user input question
def getInputAnswer(question):
    answer = ""
    while not answer:
        answer = raw_input(question + ': ')
    return answer


# Method for asking a Y/N question
def getYNAnswer(question):
    answer = ""
    while not answer:
        print ""
        answer = raw_input(question + '(y/n): ')
        print ""
        if answer == 'Y' or answer == 'y':
            answer = 'y'
        elif answer == 'N' or answer == 'n':
            answer = 'n'
        else:
            print "Bad Selection"
            answer = ""
    return answer


# Method for asking a Y/N question, return True or False
def getTFAnswer(question):
    answer = False
    while not answer:
        print ""
        ynanswer = raw_input(question + '(y/n): ')
        print ""
        if ynanswer == 'Y' or ynanswer == 'y':
            answer = True
            return answer
        elif ynanswer == 'N' or ynanswer == 'n':
            answer = False
            return answer
        else:
            print "Bad Selection"


# Return list of files from a directory
def getFileList(mypath):
    fileList = []
    if exists(mypath):
        try:
            for afile in listdir(mypath):
                if isfile(join(mypath,afile)):
                    fileList.append(afile)
        except Exception as err:
            print "Error accessing files {0} - ERROR: {1}".format(mypath, err)
    else:
        print "Path: {0} does not exist!".format(mypath)
    return fileList


# Method for requesting IP address target
def getTarget():
    print 64*"="
    print "= Scan Menu" + 52*" " + "="
    print 64*"="
    # Loop through the IPs from the file "ipsitelist.txt"
    loop = 0
    list = {};
    for line in fileinput.input('ipsitelist.txt'):
        # Print out all the IPs/SITEs
        loop += 1
        ip,site = line.split(",")
        list[str(loop)] = ip;
        print '[' + str(loop) + '] ' + ip + ' -> ' + site.strip('\n')

    print "[c] Custom IP"
    print "[x] Exit"
    print "\n"

    response = ""
    while not response:
        response = raw_input("Please select an option: ")
        if response >= "1" and response <= str(loop):
            return list[response]
        elif response == "c":
            capturedIp = ""
            while not capturedIp:
                capturedIp = raw_input("Please enter an IP: ")
                return capturedIp
        elif response == "x":
            response = "exit"
            return response
        else:
            print "Bad Selection"


# Common method for accessing multiple routers
def chooseDevices(list_dir):
    # Define the routers to deploy the config to (file/range/custom)
    method_resp = getOptionAnswer('How would you like to define the devices by IP', ['file', 'range', 'single IP', 'quit'])
    ip_list = []
    # Choose a file from a list of options
    if method_resp == "file":
        path = list_dir + "*.ips"
        files=glob.glob(path)
        if files:
            file_resp = getOptionAnswer('Choose a file to use', files)
            # Print out all the IPs/SITEs
            for line in fileinput.input(file_resp):
                line = line.rstrip()
                if line != '':
                    ip_list.append(line)
        else:
            print "No valid files in {0}".format(path)
            return ip_list

    # Define a certain range of IPs
    elif method_resp == "range":
        print "Define a network using the format X.X.X.X/Y"
        notvalid = True
        while( notvalid ):
            answer = getInputAnswer('Enter an ip address or network')
            addr_regex = re.compile("(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/\d{0,32}")
            if addr_regex.match(answer):
                notvalid = False
            else:
                print "Invalid ip address format"
        n1 = ipaddress.ip_network(answer)
        for one_ip in n1.hosts():
            ip_list.append(str(one_ip))

    # Define one or more IPs individually
    elif method_resp == "single IP":
        print 'Define a single IP Address'
        answer = ""
        while( answer != 'x' ):
            answer = getInputAnswer('Enter an ip address (x) to exit')
            if( answer != 'x'):
                ip_list.append(answer)
    else:
        print "Exiting menu..."

    # Print the IPs that will be used
    if ip_list:
        print "\n" + " " * 10 + "IPs Selected"
        print "-" * 50
        for my_ip in ip_list:
            print ' -> {0}'.format(my_ip)
        print "-" * 50
        print "Total IPs: {0}".format(len(ip_list))
    return ip_list


# Converts listDict to CSV file
def listDictCSV(myListDict, filePathName, keys):
    addKeys = True
    if (os.path.isfile(filePathName)):
        addKeys = False
    try:
        f = open(filePathName, 'a')
    except Exception as err:
        print "Failure opening file in append mode - ERROR: {0}".format(err)
        print "Be sure {0} isn't open in another program.".format(filePathName)
    else:
        if addKeys:
            #Write all the headings in the CSV
            for akey in keys[:-1]:							# Runs for every element, except the last
                f.write(akey + ",")							# Writes most elements
            f.write(keys[-1])								# Writes last element
            f.write("\n")

        for part in myListDict:
            for bkey in keys[:-1]:
                #print "Key: " + bkey + "  Value: " + str(part[bkey])
                f.write(str(part[bkey]) + ",")
            f.write(str(part[keys[-1]]))
            f.write("\n")
        f.close()
        print "\nCompleted appending to CSV."


# Converts CSV file to listDict
def csvListDict(fileName):
    myListDict = []
    try:
        with open(fileName) as myfile:
            firstline = True
            for line in myfile:
                if firstline:
                    mykeys = "".join(line.split()).split(',')
                    firstline = False
                else:
                    values = "".join(line.split()).split(',')
                    myListDict.append({mykeys[n]:values[n] for n in range(0,len(mykeys))})
    except Exception as err:
        print "Failure converting CSV to listDict - ERROR: {0}".format(err)
    return myListDict


# Converts CSV file to Dictionary
def csv_to_dict(filePathName):
    input_file = csv.DictReader(open(filePathName))
    for row in input_file:
        pass
    return row


# Gets a target code
def getCode(device, mypath):
    tar_code = ""

    # Does not have a target code, let's ask for one
    print("\n" + "*"*10)
    print("Hostname: " + device.hostname)
    print("IP: " + device.ip)
    print("Model: " + device.model)
    print("Current Code: " + device.curr_code)

    fileList = getFileList(mypath)
    if fileList:
        tar_code = getOptionAnswer("Choose an image", fileList)
    else:
        print("No images available.")
    print("*"*10 + "\n")

    return tar_code


# Get fact
def get_fact(ip, username, password, fact):
    """ Purpose: For collecting a single fact from the target system. The 'fact' must be one of the predefined ones.
        Examples:
            model, version, hostname, serialnumber,
            switch_style, last_reboot_reason, uptime,
            personality
        Parameters:
    """
    myfact = ""
    dev = Device(ip, user=username, password=password)
    try:
        dev.open()
    except Exception as err:
        return False
        # print("Unable to open connection to: {0} | ERROR: {1}").format(ip, err)
    else:
        myfact = dev.facts[fact]
        dev.close()
        if myfact:
            return myfact
        else:
            return False


# Run a single non-edit command and get the output returned
def op_command(ip, command, username, password, port=22):
    """ Purpose: For the -c flag, this function is called. It will connect to a device, run the single specified command, and return the output.
                 Paramiko is used instead of ncclient so we can pipe the command output just like on the CLI.
        Parameters:
            ip          -   String containing the IP of the remote device, used for logging purposes.
            host_name   -   The device host-name for output purposes.
            commands    -   String containing the command to be sent to the device.
            username    -   Username used to log into the device
            password    -   Password is needed because we are using paramiko for this.
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    device = ' -> Command: %s\n' % (command)
    command = command.strip() + ' | no-more\n'
    output = ''
    try:
        ssh.connect(ip, port=port, username=username, password=password)
        stdin, stdout, stderr = ssh.exec_command(command=command, timeout=900)
        stdin.close()
        # read normal output
        while not stdout.channel.exit_status_ready():
            output += stdout.read()
        stdout.close()
        # read errors
        while not stderr.channel.exit_status_ready():
            output += stderr.read()
        stderr.close()
        output = '%s\n%s' % (device, output)
        return output
    except paramiko.AuthenticationException:
        output = '*' * 45 + '\n\nBad username or password for device: %s\n' % ip
        return output


def set_command(ip, username, password, port, log_file, command_list):
    """ Purpose: This is the function for the -s or -sl flags. it will send set command(s) to a device, and commit the change.
        Parameters:
            connection  -   The NCClient manager connection to the remote device.
            ip          -   String containing the IP of the remote device, used for logging purposes.
            host_name   -   The device host-name for output purposes.
            commands    -   String containing the set command to be sent to the device, or a list of strings of multiple set commands.
                            Either way, the device will respond accordingly, and only one commit will take place.
    """
    dot = "."

    try:
        connection = run(ip, username, password, port)
    except Exception as err:
        screen_and_log(("Connection Error with {0}: Aborting Set Operation".format(ip)), log_file)
    else:
        software_info = connection.get_software_information(format='xml')
        hostname = software_info.xpath('//software-information/host-name')[0].text

        screen_and_log(("Applying configuration on {0} ({1}) ".format(hostname, ip)), log_file)
        screen_and_log(dot, log_file)
        try:
            connection.lock()
        except Exception as err:
            screen_and_log(("{0}: Unable to Lock configuration : {1}".format(ip, err)), log_file)
            return
        screen_and_log(dot, log_file)
        # Load configuration block
        try:
            connection.load_configuration(action='set', config=command_list)
        except (ConfigLoadError, Exception) as err:
            if 'statement not found' in err.message:
                #print "Bypassing warning through message"
                pass
            #elif err.rpc_error['severity'] == 'warning':
            #    print "Bypassing warning through severity"
            #    pass
            else:
                screen_and_log(("{0}: Unable to Load the configuration : {1}".format(ip, err)), log_file)
                screen_and_log(("{0}: Unlocking the configuration".format(ip)), log_file)
                try:
                    connection.unlock()
                except Exception as err:
                    screen_and_log(("{0}: Unable to Unlock the configuration : {1}".format(ip, err)), log_file)
                connection.close_session()
                return
        screen_and_log(dot, log_file)
        # Commit configuration block
        try:
            connection.commit()
        except Exception as err:
            screen_and_log(("{0}: Commit fails : {1}".format(ip, err)), log_file)
            return
        screen_and_log(dot, log_file)
        # Unlock configuration block
        try:
            connection.unlock()
        except Exception as err:
            screen_and_log(("{0}: Unable to Unlock the configuration : {1}".format(ip, err)), log_file)
            connection.close_session()
            return
        connection.close_session()
        screen_and_log(" Completed!\n", log_file)


def enable_netconf(ip, username, password, port, log_file=None):
    """ Purpose: To enable the netconf ssh service on a device that does not have it.
    """
    netconf_command = "set system services netconf ssh"
    print("Trying to enable NETCONF on {0}").format(ip)
    try:
        set_command(ip, username, password, port, log_file, netconf_command)
    except Exception as err:
        print "Failed to enable NETCONF."
        return False
    else:
        print "Successfully enabled NETCONF!"
        return True


def run(ip, username, password, port):
    """ Purpose: To open an NCClient manager session to the device, and run the appropriate function against the device.
        Parameters:
            ip          -   String of the IP of the device, to open the connection, and for logging purposes.
            username    -   The string username used to connect to the device.
            password    -   The string password used to connect to the device.
    """
    output = ''
    try:
        #print "{0}: Establishing connection...".format(ip)
        connection = manager.connect(host=ip,
                                     port=port,
                                     username=username,
                                     password=password,
                                     timeout=15,
                                     device_params={'name':'junos'},
                                     hostkey_verify=False)
        connection.timeout = 300
    except errors.SSHError:
        output = '*' * 45 + '\n\nUnable to connect to device: %s on port: %s\n' % (ip, port)
        print output
    except errors.AuthenticationError:
        output = '*' * 45 + '\n\nBad username or password for device: %s\n' % ip
        print output
    else:
        return connection


def load_with_pyez(merge_opt, overwrite_opt, format_opt, conf_file, log_file, ip, hostname, username, password):
    """ Purpose: Perform the actual loading of the config file. Catch any errors.
        Parameters:
            format_opt      -   defines the format of input "set" or "hierarchical"
            merge_opt       -   the merge options selection, "loadmerge"
            overwrite_opt   -   the overwrite option selection, "loadoverwrite"
            conf_file       -   the configuration file name, including path and filename
            log_file        -   the log file name, including path and filename
            ip              -   ip address of device
            hostname        -   device hostname
            username        -   username for logging in
            password        -   password for username
    """
    dot = "."
    screen_and_log(("Applying configuration on {0} ({1}) ".format(hostname, ip)), log_file)
    screen_and_log(dot, log_file)
    try:
        dev = Device(ip, user=username, password=password)
        dev.open()
    except ConnectError as err:
        screen_and_log(("{0}: Cannot connect to device : {1}".format(ip, err)), log_file)
        return
    dev.bind(cu=Config)


    #print("Try locking the configuration...")
    screen_and_log(dot, log_file)
    try:
        dev.cu.lock()
    except LockError as err:
        screen_and_log(("{0}: Unable to lock configuration : {1}".format(ip, err)), log_file)
        dev.close()
        return

    #print("Try loading configuration changes...")
    screen_and_log(dot, log_file)
    try:
        if format is None:
            dev.cu.load(path=conf_file, merge=merge_opt, overwrite=overwrite_opt)
        else:
            dev.cu.load(path=conf_file, merge=merge_opt, format="set")
    except (ConfigLoadError, Exception) as err:
        if err.rpc_error['severity'] == 'warning':
            pass
        elif 'statement not found' in err.message:
            pass
        else:
            screen_and_log(("{0}: Unable to load configuration changes : {1}".format(ip, err)), log_file)
            screen_and_log(("{0}: Unlocking the configuration".format(ip)), log_file)
            try:
                dev.cu.unlock()
            except UnlockError as err:
                screen_and_log(("{0}: Unable to unlock configuration : {1}".format(ip, err)), log_file)
            dev.close()
            return

    #print("Try committing the configuration...")
    screen_and_log(dot, log_file)
    try:
        dev.cu.commit()
    except CommitError as err:
        screen_and_log(("{0}: Unable to commit configuration : {1}".format(ip, err)), log_file)
        screen_and_log(("{0}: Unlocking the configuration".format(ip)), log_file)
        try:
            dev.cu.unlock()
        except UnlockError as err:
            screen_and_log(("{0}: Unable to unlock configuration : {1}".format(ip, err)), log_file)
        dev.close()
        return

    #print("Try Unlocking the configuration...")
    screen_and_log(dot, log_file)
    try:
        dev.cu.unlock()
    except UnlockError as err:
        screen_and_log(("{0}: Unable to unlock configuration : {1}".format(ip, err)), log_file)
        dev.close()
        return

    # End the NETCONF session and close the connection
    dev.close()
    screen_and_log((" Completed!\n"), log_file)


# Prints output to a log file and the screen
def screen_and_log(output, log_file=None):
    if log_file is not None:
        with open(log_file, 'a') as myfile:
            myfile.write(output)
    sys.stdout.write(output)


# Creates list from a text file
def txt_to_list(txt_file):
    command_list = []
    try:
        with open(txt_file) as f:
            command_list = f.read().splitlines()
    except Exception as err:
        print "Error turning file into list. ERROR: {0}".format(err)

    return command_list


# Pings the provided IP and returns True/False, works on Windows or Linux/Mac
def ping(ip):
    """ Purpose: Determine if an IP is pingable
    :param ip: IP address of host to ping
    :return: True if ping successful
    """
    with open(os.devnull, 'w') as DEVNULL:
        try:
            # Check for Windows or Linux/MAC
            ping_param = "-n" if platform.system().lower() == "windows" else "-c"
            subprocess.check_call(
                ['ping', ping_param, '3', ip],
                stdout=DEVNULL,
                stderr=DEVNULL
            )
            return True
        except subprocess.CalledProcessError:
            return False

# Import variables into config file