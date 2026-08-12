#from datetime import datetime,timedelta
import statistics as st

TIME_WINDOW = 60
NUM_FAIL = 5
VAR_UHD = 3
NUM_LOC = 3
TIME_WINDOW_LOCATION = 10
NUM_FAIL = 4
DAY_TO_MIN = 1440
HOUR_TO_MIN = 60

def rule_brute_force(parsed_data):
    """
    Detect brute force attempts by sorting the data using ip address,
    using sliding window to check for NUM_FAIL attempts within TIME_WINDOW
    returning flag with list of all usernames used during this attempt
    """
    sorted_data = sorted(parsed_data,key=lambda x: x["ip"])
    rule_flags = []
    ip_add = sorted_data[0]["ip"]
    ip_count = 1
    sw_l = 0
    sw_r = 1
    ts = [sorted_data[0]["ts"]]
    bfd_users = {sorted_data[0]["user"]}
    sorted_data.append(sorted_data[0].copy())
    for i in range(1,len(sorted_data)):
        if ip_add != sorted_data[i]["ip"]:
            if ip_count >= NUM_FAIL:
                ts.sort()
                ts_num = 2
                while (sw_r > sw_l and sw_r < ip_count):
                    duration = (ts[sw_r] - ts[sw_l]).total_seconds()
                    if duration <= TIME_WINDOW:
                        ts_num += 1
                    if duration > TIME_WINDOW:
                        ts_num -= 1
                        sw_l += 1
                        continue
                    if ts_num >= NUM_FAIL:
                        rule_flags.append({
                            "rule":"bfd",
                            "severity":"CRITICAL",
                            "ip":ip_add,
                            "user":bfd_users.copy(),
                            "count":ts_num,
                            "time":ts[sw_r]
                        })
                        ts_num = 2
                        sw_l = sw_r + 1
                        sw_r += 2
                        continue
                    sw_r += 1
                
            ip_add = sorted_data[i]["ip"]
            ip_count = 0
            ts.clear()
            bfd_users.clear()
            if sorted_data[i]["status"].lower() != "accepted":
                ts.append(sorted_data[i]["ts"])
                ip_count = 1
            bfd_users.add(sorted_data[i]["user"])
            sw_l = 0
            sw_r = 1
            continue

        if sorted_data[i]["status"].lower() == "accepted":
            continue

        if sorted_data[i]["ip"] == ip_add:
            ts.append(sorted_data[i]["ts"])
            bfd_users.add(sorted_data[i]["user"])
            ip_count += 1
            continue
            
    return rule_flags

def unusual_hour_detection(parsed_data):
    """
    Detects unusual successful login based on
    +/- VAR_UHD*sigma variation for login time for the user
    sorts data by user and process timestamp for each login
    by same user.
    """
    rule_flags = []
    sorted_data = sorted(parsed_data,key = lambda x: x["user"])
    sorted_data.append(sorted_data[0])
    current_user = sorted_data[0]["user"]
    next_user = sorted_data[0]["user"]
    user_ts = []
    for entry in sorted_data:
        if entry["status"].lower() == "accepted":
            next_user = entry["user"]
            if next_user != current_user:
                if len(user_ts) < 3:
                    user_ts.clear()
                    user_ts.append(entry)
                    current_user = next_user
                    continue
                
                user_ts_mod = []
                for x in user_ts:
                    user_ts_mod.append(int(x["ts"].hour*HOUR_TO_MIN + x["ts"].minute))
                ts_mean = st.mean(user_ts_mod)
                ts_std = st.stdev(user_ts_mod)
                ts_min = (ts_mean - VAR_UHD*ts_std)
                if ts_min < 0:
                    ts_min = 0
                ts_max = (ts_mean + VAR_UHD*ts_std)
                if ts_max >= DAY_TO_MIN:
                    ts_max = DAY_TO_MIN - 1
                for x in user_ts:
                    x_ts = (x["ts"].hour*HOUR_TO_MIN + x["ts"].minute)
                    if (x_ts < ts_min) or (x_ts > ts_max):
                        rule_flags.append({
                            "rule":"uhd",
                            "severity":"WARNING",
                            "user":x["user"],
                            "ip":x["ip"],
                            "time":x["ts"],
                            "normal_time":[ts_min,ts_max]
                        })
                user_ts.clear()
                user_ts_mod.clear()
                current_user = next_user
            user_ts.append(entry)

    return rule_flags

def multi_ip_detection(parsed_data):
    """

    """
    rule_flags = []
    sorted_data = sorted(parsed_data,key = lambda x: x["user"])
    sorted_data.append(sorted_data[0])
    current_user = sorted_data[0]["user"]
    next_user = sorted_data[0]["user"]
    user_ts = []

    for entry in sorted_data:
        if entry["status"].lower() == "accepted":
            next_user = entry["user"]
            if next_user != current_user:
                if len(user_ts) < NUM_LOC :
                    user_ts.clear()
                    user_ts.append(entry)
                    current_user = next_user
                    continue
                user_ts = sorted(user_ts,key = lambda x: x["ts"])
                sw_l = 0
                sw_r = 1
                while( sw_r < len(user_ts) and sw_l <= sw_r):
                    num_ip = 0
                    ip_list = set()
                    if((user_ts[sw_r]["ts"] - user_ts[sw_l]["ts"]).total_seconds() / HOUR_TO_MIN > TIME_WINDOW_LOCATION):
                        #sw_r += 1
                        sw_l += 1
                        continue
                    for y in range(sw_r - sw_l + 1):
                        ip_list.add(user_ts[sw_l + y]["ip"])
                    num_ip = len(ip_list)
                    if num_ip >= NUM_LOC:
                        rule_flags.append({
                            "rule":"mid",
                            "severity":"WARNING",
                            "user":user_ts[sw_l]["user"],
                            "ip":ip_list.copy(),
                            "time":user_ts[sw_l]["ts"]
                        })
                        sw_l = sw_r + 1
                        sw_r = sw_r + 2
                    else:
                       # sw_l += 1
                        sw_r += 1
                    ip_list.clear()
                
                user_ts.clear()
                current_user = next_user
            user_ts.append(entry)

    return rule_flags

def fail_success_detection(parsed_data):
    """

    """
    rule_flags = []
    sorted_data = sorted(parsed_data,key = lambda x: x["user"])
    sorted_data.append(sorted_data[0])
    current_user = sorted_data[0]["user"]
    next_user = sorted_data[0]["user"]
    user_ts = []

    for entry in sorted_data:
        next_user = entry["user"]
        if next_user != current_user:
            if len(user_ts) < NUM_FAIL :
                user_ts.clear()
                user_ts.append(entry)
                current_user = next_user
                continue
            user_ts = sorted(user_ts,key = lambda x: x["ts"])
            num_fail = 0
            ip_list = set()
            for x in user_ts:
                if x["status"].lower() != "accepted":
                    num_fail += 1
                    ip_list.add(x["ip"])
                else:
                    if num_fail < NUM_FAIL:
                        num_fail = 0
                        ip_list.clear()
                        continue
                    if x["ip"] in ip_list:
                        if num_fail > 3*NUM_FAIL:
                            warn = "CRITICAL"
                        else:
                            warn = "WARNING"
                        rule_flags.append({
                            "rule":"fsd",
                            "severity":warn ,
                            "user":x["user"],
                            "ip":x["ip"],
                            "time":x["ts"],
                            "count":num_fail
                        })
                        num_fail = 0
                        ip_list.clear()
            
            user_ts.clear()
            current_user = next_user
        user_ts.append(entry)

    return rule_flags


