"""parser.py gets timestamp,status,process,username,ip_add data from the log file."""

from datetime import datetime
import logging
import re

logger = logging.getLogger(__name__)
logging.basicConfig(filename="outputs/parser.log", level=logging.INFO)


def parse_log(filepath):
    """Uses regex to parse the log data into python dictionary
    with timestamp, status, process, username, ip_add key values
    """
    with open(filepath, "r") as log_file:
        logs = log_file.readlines()

    parsed_data = []

    for i in range(len(logs)):
        # these regex are based on existing logs, will need tweeking if log format is modified
        if timestamp := re.search(r"^.*:\d{2}", logs[i]):
            timestamp = re.split(r"[ :]", timestamp.group())
            month = datetime.strptime(timestamp[0], "%b").month
            timestamp_dt = datetime(
                2026,
                month,
                int(timestamp[1]),
                int(timestamp[2]),
                int(timestamp[3]),
                int(timestamp[4]),
            )
            # by default year is hard-coded to 2026 since it is not relavent when analysing monthly data
        else:
            timestamp_dt = None

        if status := re.search(r"\]:\s\w*", logs[i]):
            status = status.group()[3:]
            if status.lower() == "connection" or status.lower() == "disconnected":
                continue

        process = re.search(r"\w{4}\[\d*\]", logs[i])
        if process is None or process.group()[:4].lower() != "sshd":
            # skipping non sshd logs

            logger.info(
                "log command type is non sshd: %s",
                logs[i],
            )
            continue

        if username := re.search(r"\w*\sfrom", logs[i]):
            username = username.group()[:-5]

        if ip_add := re.search(r"\d*\.\d*\.\d*\.\d*", logs[i]):
            ip_add = ip_add.group()

        if None in (timestamp_dt, username, ip_add, status):
            logger.info(
                "some fields are not found in the original logs for: %s",
                logs[i],
            )

        else:
            parsed_data.append(
                {
                    "ts": timestamp_dt,
                    "user": username,
                    "ip": ip_add,
                    "status": status,
                    "sudo": None,
                },
            )

    return parsed_data
