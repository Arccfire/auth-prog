import re
from datetime import datetime

def parse_log(filepath):
    """
    Uses regex to parse the log data into python dictionary
    with timestamp, status, process, username, ip_add key values
    """
    
    log_file = open(filepath,"r")
    logs = log_file.readlines()
    log_file.close()

    parsed_data = []

    for i in range(0,len(logs)):
        # these regex are based on existing logs, will need tweeking if log format is modified
        if (timestamp := re.search(r"^.*:\d{2}",logs[i])):
            timestamp = re.split(r"[ :]",timestamp.group())
            month = datetime.strptime(timestamp[0],"%b").month
            timestamp_dt = datetime(2026,month,int(timestamp[1]),int(timestamp[2]),int(timestamp[3]),int(timestamp[4]))
            # by default year is hard-coded to 2026 since it is not relavent when analysing monthly data


        if (status := re.search(r"\]:\s\w*",logs[i])):
            status = status.group()[3:]
            if status.lower() == "connection" or status.lower() == "disconnection":
                continue

        if (process := re.search(r"\w{4}\[\d*\]",logs[i])):
            process = process.group()[:4]
            if process.lower() == "sudo":
                #for future use, incase expansion to original requirements is needed
                #sudo_esc = re.search(r"sudo\[\d*\]:\s",logs[i])
                continue

        if (username := re.search(r"\w*\sfrom",logs[i])):
            username = username.group()[:-5]

        if(ip_add := re.search(r"\d*\.\d*\.\d*\.\d*",logs[i])):
            ip_add = ip_add.group()

        parsed_data.append({"ts":timestamp_dt,"user":username,"ip":ip_add,"status":status,"sudo":None})

    return parsed_data
    # some print statments for debugging
    #
    #   print(logs[i])
    #   print(timestamp)
    #   print(process)
    #   print(status)
    #   print(username)
    #   print(ip_add)
