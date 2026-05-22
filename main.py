from pathlib import Path
from parser import parse_log
from rules import rule_brute_force, unusual_hour_detection, multi_ip_detection, fail_success_detection
from reporter import flag_formater, flag_summary, csv_export, summary_report, timeline_chart


def main():
    log_filepath = Path(str(input("Welcome to auth-prog! Please enter filepath to logs file: ")))
    while( not log_filepath.is_file()):
        print("File doesn't exist at provided filepath")
        log_filepath = Path(str(input("Please re-enter filepath to logs file: ")))
    parsed_data = parse_log(log_filepath)
    r1 = rule_brute_force(parsed_data)
    r2 = unusual_hour_detection(parsed_data)
    r3 =  multi_ip_detection(parsed_data)
    r4 =  fail_success_detection(parsed_data)
    master_flag_list = sorted((r1+r2+r3+r4),key = lambda x: x["time"])
    if len(master_flag_list) == 0:
        print("No anomalies found")
        print("Thank you for using auth-prog!")
        return
    flag_formater(master_flag_list)
    flag_summary(master_flag_list)
    csv_export(master_flag_list)
    summary_report(master_flag_list)
    timeline_chart(master_flag_list)


    print("Thank you for using auth-prog!")

if __name__ == "__main__":
    main()
