import statistics as st
from datetime import datetime as dt

import matplotlib.pyplot as plt
import pandas as pd

VAR_REPORT = 0.5
DAY_TO_MIN = 1440
HOUR_TO_MIN = 60

CURR_TIME = dt.now().replace(microsecond=0)

def flag_formater(flag_list):
    """ """
    rule_expansion = {
        "bfd": "brute force detected",
        "uhd": "unusual hours detected",
        "mid": "multiple ip detected",
        "fsd": "fail -> success detected",
    }
    for flag in flag_list:
        print("[" + flag["severity"] + "] " + rule_expansion[flag["rule"]])
        print(" Time: ", flag["time"])
        if flag["rule"] == "bfd":
            s = ""
            for x in flag["user"]:
                s = s + x + ", "
            print(" User: " + s[:-2])
        else:
            print(" User: ", flag["user"])
        if flag["rule"] == "mid":
            s = ""
            for x in flag["ip"]:
                s = s + x + ", "
            print(" IPs: " + s[:-2])
        else:
            print(" IP: ", flag["ip"])

        if flag["rule"] == "uhd":
            nh_min = f'{int(flag["normal_time"][0]) // HOUR_TO_MIN:02d}:{int(flag["normal_time"][0])%HOUR_TO_MIN:02d}'
            nh_max = f'{int(flag["normal_time"][1]) // HOUR_TO_MIN:02d}:{int(flag["normal_time"][1])%HOUR_TO_MIN:02d}'
            print(" Normal Hours: ", nh_min, " - ", nh_max)
        if flag["rule"] == "fsd":
            print(" Fail Count: ", flag["count"])

        print()


def most_attacking_ip(flag_list):
    """ """
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

    for k, v in ip_hash.items():
        if max_atcks < v:
            max_atcks = v
            max_atck_ip = k
    return (max_atck_ip, max_atcks)


def most_attacked_user(flag_list):
    """ """
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
    for k, v in user_hash.items():
        if max_tar_num < v:
            max_tar_num = v
            max_tar_user = k
    return (max_tar_user, max_tar_num)


def flag_summary(flag_list):
    """ """
    num_warn = 0
    num_crit = 0
    for flag in flag_list:
        if flag["severity"] == "WARNING":
            num_warn += 1
        else:
            num_crit += 1
    max_tar_user, max_tar_num = most_attacked_user(flag_list)

    print("-------------------------------------")
    print("Total WARNING: ", num_warn)
    print("Total CRITICAL: ", num_crit)
    print("Most Targeted: ", max_tar_user)
    print("Number of attack on most target user: ", max_tar_num)
    print("-------------------------------------")


def csv_export(flag_list):
    """ """
    df = pd.DataFrame(flag_list)
    # pd.set_option('display.max_columns', None)
    out_file_name = (
        "outputs/"
        + str(CURR_TIME.strftime("%Y-%m-%d_%H-%M-%S"))
        + ".csv"
    )
    df.to_csv(out_file_name, index=False, sep=";")
    print("Logs for ", len(df), " flags is exported to outputs directory")


def summary_report(flag_list):
    """ """
    num_rule = {"bfd": 0, "uhd": 0, "mid": 0, "fsd": 0}  # bfd, uhd, mid, fsd
    ts = []
    num_crit = 0
    num_warn = 0
    for flag in flag_list:
        num_rule[flag["rule"]] += 1
        ts.append(int(flag["time"].hour * HOUR_TO_MIN + flag["time"].minute))
        if flag["severity"] == "WARNING":
            num_warn += 1
        else:
            num_crit += 1
    if len(ts) > 1:
        ts_stdev = st.stdev(ts)
        ts_mean = st.mean(ts)
    else:
        ts_stdev = 0
        ts_mean = 0
    ts_sub = ts_mean - VAR_REPORT * ts_stdev
    ts_add = ts_mean + VAR_REPORT * ts_stdev
    ts_sub = max(ts_sub, 0)
    if ts_add >= DAY_TO_MIN:
        ts_add = DAY_TO_MIN - 1
    nh_min = f'{int(flag["normal_time"][0]) // HOUR_TO_MIN:02d}:{int(flag["normal_time"][0])%HOUR_TO_MIN:02d}'
    ts_min = f'{int(ts_sub)//HOUR_TO_MIN:02d}:{int(ts_sub)%HOUR_TO_MIN:02d}'
    ts_max = f'{int(ts_add)//HOUR_TO_MIN:02d}:{int(ts_add)%HOUR_TO_MIN:02d}'
    ts_num = 0
    for flag in flag_list:
        x = int(flag["time"].hour * HOUR_TO_MIN + flag["time"].minute)
        if (x <= ts_add) and (x >= ts_sub):
            ts_num += 1
    max_tar_user, max_tar_num = most_attacked_user(flag_list)
    max_atck_ip, max_num_atck = most_attacking_ip(flag_list)
    filename = (
        "outputs/"
        + str(CURR_TIME.strftime("%Y-%m-%d_%H-%M-%S"))
        + ".txt"
    )
    with  open(filename, "w") as summary_file:
        summary_file.write(f"""
    -------------------------------------
        SECURITY LOG ANOMALY REPORT
        Generated: {CURR_TIME}
    -------------------------------------

    OVERVIEW
    -------------------------------------
    Total Flags Raised   : {num_crit + num_warn}
        CRITICAL         : {num_crit}
        WARNING          : {num_warn}

    FLAGS BY RULE
    -------------------------------------
    Brute Force          : {num_rule["bfd"]}
    Unusual Hour Login   : {num_rule["uhd"]}
    Multiple IP Anomaly  : {num_rule["mid"]}
    Fail → Success       : {num_rule["fsd"]}

    PEAK ATTACK TIME (+/- {VAR_REPORT} sigma)
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
    print(
        "Summary txt report for ",
        num_warn + num_crit,
        " flags is exported to outputs directory",
    )

def timeline_chart(flag_list):
    """ """
    # flag_list = sorted(flag_list, key=lambda x: x["time"].hour)
    timeline_warn = dict.fromkeys(range(24), 0)
    timeline_crit = dict.fromkeys(range(24), 0)
    for flag in flag_list:
        if flag["severity"] == "WARNING":
            timeline_warn[flag["time"].hour] += 1
        else:
            timeline_crit[flag["time"].hour] += 1

    plt.xticks(range(24))
    plt.grid(axis="y", linestyle="--", alpha=0.5)
    plt.title(f"Flags Timeline by Hour\n{CURR_TIME}")
    plt.bar(
        list(timeline_crit.keys()),
        list(timeline_crit.values()),
        label="CRITICAL",
        color="red",
    )
    plt.bar(
        list(timeline_warn.keys()),
        list(timeline_warn.values()),
        label="WARNING",
        color="orange",
        alpha=0.6,
        bottom=list(timeline_crit.values()),
    )
    plt.legend()
    plotname = (
        "outputs/"
        + str(CURR_TIME.strftime("%Y-%m-%d_%H-%M-%S"))
        + ".png"
    )
    plt.savefig(plotname)
    # plt.clf()
    plt.close()
    print("Timeline chart is saved to outputs directory")
