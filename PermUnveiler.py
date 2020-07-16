from androguard.misc import AnalyzeAPK
from termcolor import colored
import argparse
import androguard


#get apk path from the user
#color it
#make malicious list


class PermissionChecker:

    def __init__(self):
        self.dangerzone = ["READ_CALENDAR",
                    "WRITE_CALENDAR",
                    "CAMERA",
                    "READ_CONTACTS",
                    "WRITE_CONTACTS",
                    "GET_ACCOUNTS",
                    "ACCESS_FINE_LOCATION",
                    "ACCESS_COARSE_LOCATION",
                    "RECORD_AUDIO",
                    "READ_PHONE_STATE",
                    "READ_PHONE_NUMBERS", 
                    "CALL_PHONE",
                    "ANSWER_PHONE_CALLS ",
                    "READ_CALL_LOG",
                    "WRITE_CALL_LOG",
                    "ADD_VOICEMAIL",
                    "USE_SIP",
                    "PROCESS_OUTGOING_CALLS",
                    "BODY_SENSORS",
                    "SEND_SMS",
                    "RECEIVE_SMS",
                    "READ_SMS",
                    "RECEIVE_WAP_PUSH",
                    "RECEIVE_MMS",
                    "READ_EXTERNAL_STORAGE",
                    "WRITE_EXTERNAL_STORAGE"]

    def argparsing(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("-p", "--path", action="store", dest="apkpath", type=str , help="Enter path to the apk")
        args = parser.parse_args()
        self.apkpath = args.apkpath
        return self.apkpath
        

    def getPermissions(self,apkpath):
        apk, dalvik, analysis = AnalyzeAPK(apkpath)
        self.permissions = apk.get_permissions()
        return self.permissions

    def color_n_print(self,permissions):
        
        for cursor in permissions:
            if cursor in self.dangerzone:
                print(colored(cursor,"red"))
            print(colored(cursor,"green"))

print("""

 ____  _____ ____  __  __ _   _ _   ___     _______ ___ _     _____ ____
|  _ \\| ____|  _ \\|  \\/  | | | | \\ | \\ \\   / / ____|_ _| |   | ____|  _ \\
| |_) |  _| | |_) | |\\/| | | | |  \\| |\\ \\ / /|  _|  | || |   |  _| | |_) |
|  __/| |___|  _ <| |  | | |_| | |\\  | \\ V / | |___ | || |___| |___|  _ <
|_|   |_____|_| \\_\\_|  |_|\___/|_| \\_|  \\_/  |_____|___|_____|_____|_| \\_\\


""")
permchck = PermissionChecker()
apkpath = permchck.argparsing()
permissions = permchck.getPermissions(apkpath)
permchck.color_n_print(permissions)
