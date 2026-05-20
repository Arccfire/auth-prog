from parser import parse_log
from rules import rule_brute_force, unusual_hour_detection, multi_ip_detection

def main():
    print("Hello from auth-prog!")
    parsed_data = parse_log("logs/auth.log")
    #x = rule_brute_force(parsed_data)
    #y = unusual_hour_detection(parsed_data)
    z =  multi_ip_detection(parsed_data)
    for x in z:
        print(x)

    print("Bye Bye from auth-prog!")

if __name__ == "__main__":
    main()
