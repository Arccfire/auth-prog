import pandas as pd
from datetime import datetime as dt
import statistics as st
import matplotlib.pyplot as plt

VAR = 0.5

def flag_formater(flag_list):

    rule_expansion = {
        "bfd":"brute force detected",
        "uhd":"unusual hours detected",
        "mid":"multiple ip detected",
        "fsd":"fail -> success detected"
    }
    for flag in flag_list:
        print("["+flag["severity"]+"] " + rule_expansion[flag["rule"]])
        print(" Time: ",flag["time"])
        if flag["rule"] == "bfd":
            s = ""
            for x in flag["user"]:
                s = s + x + ", "
            print(" User: " + s[:-2])
        else:
            print(" User: ",flag["user"])
        if flag["rule"] == "mid":
            s = ""
            for x in flag["ip"]:
                s = s + x + ", "
            print(" IPs: " + s[:-2])
        else:
            print(" IP: ",flag["ip"])
        if flag["rule"] == "uhd":
            nh_min = str(int(flag["normal_time"][0]//60)) + ":" + str(int(flag["normal_time"][0])%60)
            nh_max = str(int(flag["normal_time"][1]//60)) + ":" + str(int(flag["normal_time"][1])%60)
            print(" Normal Hours: ",nh_min, " - ", nh_max)
        if flag["rule"] == "fsd":
            print(" Fail Count: ",flag["count"])

        print("")
    return

def most_attacking_ip(flag_list):
    ip_hash = {}
    for flag in flag_list:
        if flag["rule"] == "mid":
            for x in flag["ip"]:
                if x not in ip_hash:
                    ip_hash[x] = 1
                else:
                    ip_hash[x] += 1
        else:
            x = flag["ip"]
            if x not in ip_hash:
                ip_hash[x] = 1
            else:
                ip_hash[x] += 1
        max_atck_ip = ""
        max_atcks = 0

    for k,v in ip_hash.items():
        if max_atcks < v:
            max_atcks = v
            max_atck_ip = k
    return (max_atck_ip,max_atcks)

def most_attacked_user(flag_list):
    user_hash = {}
    for flag in flag_list:
        if flag["rule"] == "bfd":
            for x in flag["user"]:
                if x not in user_hash:
                    user_hash[x] = 1
                else:
                    user_hash[x] += 1
        else:
            x = flag["user"]
            if x not in user_hash:
                user_hash[x] = 1
            else:
                user_hash[x] += 1
    max_tar_user = ""
    max_tar_num = 0
    for k,v in user_hash.items():
        if max_tar_num < v:
            max_tar_num = v
            max_tar_user = k
    return (max_tar_user,max_tar_num)

def flag_summary(flag_list):
    num_warn = 0
    num_crit = 0
    for flag in flag_list:
        if flag["severity"] == "WARNING":
            num_warn += 1
        else:
            num_crit += 1
    max_tar_user,max_tar_num = most_attacked_user(flag_list)

    print("-------------------------------------")
    print("Total WARNING: ",num_warn)
    print("Total CRITICAL: ",num_crit)
    print("Most Targeted: ",max_tar_user)
    print("-------------------------------------")
    return

def csv_export(flag_list):
    df = pd.DataFrame(flag_list)
    #pd.set_option('display.max_columns', None)
    out_file_name = "outputs/"+str(dt.now().replace(microsecond=0).strftime("%Y-%m-%d_%H-%M-%S"))+".csv"
    df.to_csv(out_file_name,index=False,sep=";")
    print("Logs for ",len(df)," flags is exported to outputs directory")
    return

def summary_report(flag_list):
    num_rule = {"bfd":0,"uhd":0,"mid":0,"fsd":0} # bfd, uhd, mid, fsd
    ts = []
    num_crit = 0
    num_warn = 0
    for flag in flag_list:
        num_rule[flag["rule"]] += 1
        ts.append(int(flag["time"].hour*60 + flag["time"].minute))
        if flag["severity"] == "WARNING":
            num_warn += 1
        else:
            num_crit += 1
    ts_mean = st.mean(ts)
    ts_stdev = st.stdev(ts)
    ts_sub = ts_mean - VAR*ts_stdev
    ts_add = ts_mean + VAR*ts_stdev
    if ts_sub < 0:
        ts_sub = 0
    if ts_add >= 1440:
        ts_add = 1439
    ts_min = str(int(ts_sub)//60)+":"
    if(int(ts_sub)%60 < 10): 
        ts_min += "0" + str(int(ts_sub)%60)
    else:
        ts_min += str(int(ts_sub)%60)

    ts_max = str(int(ts_add)//60)+":"
    if(int(ts_add)%60 < 10): 
        ts_max += "0" + str(int(ts_add)%60)
    else:
        ts_max += str(int(ts_add)%60)

    ts_num = 0
    for flag in flag_list:
        x = int(flag["time"].hour*60 + flag["time"].minute)
        if  (x < ts_add) and (x > ts_sub):
            ts_num += 1
    max_tar_user,max_tar_num = most_attacked_user(flag_list)
    max_atck_ip, max_num_atck = most_attacking_ip(flag_list)
    filename = "outputs/" + str(dt.now().replace(microsecond=0).strftime("%Y-%m-%d_%H-%M-%S")) + ".txt"
    summary_file = open(filename,"w")
    
    summary_file.write(f"""
    -------------------------------------
        SECURITY LOG ANOMALY REPORT
        Generated: {dt.now().replace(microsecond=0)}
    -------------------------------------

    OVERVIEW
    -------------------------------------
    Total Flags Raised   : {num_crit+num_warn}
        CRITICAL         : {num_crit}
        WARNING          : {num_warn}

    FLAGS BY RULE
    -------------------------------------
    Brute Force          : {num_rule["bfd"]}
    Unusual Hour Login   : {num_rule["uhd"]}
    Multiple IP Anomaly  : {num_rule["mid"]}
    Fail → Success       : {num_rule["fsd"]}

    PEAK ATTACK TIME (+/- {VAR} sigma)
    -------------------------------------
    Hour                 : {ts_min} - {ts_max}
    Flags in this time   : {ts_num}

    MOST TARGETED USER
    -------------------------------------
    User                 : {max_tar_user}
    Total flags          : {max_tar_num}

    MOST ACTIVE ATTACKER IP
    -------------------------------------
    IP                   : {max_atck_ip}
    Total flags          : {max_num_atck}
    """)
    summary_file.close()
    print("Summary txt report for ",num_warn+num_crit," flags is exported to outputs directory")
    return

def timeline_chart(flag_list):
    flag_list = sorted(flag_list,key = lambda x: x["time"].hour)
    timeline_warn = {i: 0 for i in range(24)}
    timeline_crit = {i: 0 for i in range(24)}
    for flag in flag_list:
        if flag["severity"] == "WARNING":
            timeline_warn[flag["time"].hour] += 1
        else:
            timeline_crit[flag["time"].hour] += 1

    plt.xticks(range(24))
    plt.grid(axis="y", linestyle="--", alpha=0.5)
    plt.title(f"Flags Timeline by Hour\n{dt.now().replace(microsecond=0)}")
    plt.bar(list(timeline_crit.keys()), list(timeline_crit.values()), label="WARNING", color="red")
    plt.bar(list(timeline_warn.keys()), list(timeline_warn.values()), label="CRITICAL", color="orange", alpha=0.6,bottom=list(timeline_crit.values()))
    plt.legend()
    plotname = "outputs/"+str(dt.now().replace(microsecond=0).strftime("%Y-%m-%d_%H-%M-%S"))+".png"
    plt.savefig(plotname)
    plt.clf()
    print("Timeline chart is saved to outputs directory")


    return



