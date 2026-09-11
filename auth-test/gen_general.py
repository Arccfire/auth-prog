"""Generate a 2000-line auth.log statistically similar to the original.

Profile taken from the supplied logs/auth.log:
  ~66% Accepted, ~17% Failed, ~5% Connection closed, ~4% Disconnected,
  ~4% sudo, ~4% Invalid user guest.
Same 7 users, same home-IP mapping, same per-user login-hour means/sigmas.
Spans Feb 01 - Mar 02 2026 (the original was January) so a month rollover
is exercised too.
"""

import random
from datetime import datetime, timedelta

random.seed(20260901)

TARGET = 2000
START = datetime(2026, 2, 1, 0, 0, 0)
DAYS = 30

# user -> (home ip, mean login minute-of-day, sigma minutes)
USERS = {
    "admin":  ("192.168.1.10", 13.28 * 60, 2.79 * 60),
    "deploy": ("10.0.0.5",     12.89 * 60, 1.99 * 60),
    "john":   ("192.168.1.20", 12.68 * 60, 2.73 * 60),
    "mike":   ("192.168.1.40", 13.33 * 60, 2.84 * 60),
    "priya":  ("192.168.1.50", 12.67 * 60, 2.73 * 60),
    "root":   ("192.168.1.5",  13.20 * 60, 3.22 * 60),
    "sarah":  ("192.168.1.30", 14.53 * 60, 2.95 * 60),
}
HOSTILE = ["203.0.113.42", "123.45.67.89", "91.108.4.10", "45.33.32.156",
           "198.51.100.22", "77.88.55.80", "103.21.244.0", "185.220.101.5"]
SUDO_USERS = ["john", "mike", "sarah"]

# accepted-login weights roughly matching the original per-user counts
ACC_W = {"priya": 186, "sarah": 174, "admin": 163, "root": 162,
         "john": 155, "deploy": 155, "mike": 154}
FAIL_W = {"root": 127, "john": 51, "admin": 48, "deploy": 22,
          "sarah": 17, "priya": 16, "mike": 16}


def pid():
    return random.randint(1000, 9999)


def port():
    return random.randint(1024, 65535)


def stamp(dt):
    return dt.strftime("%b %d %H:%M:%S")


def rand_day():
    return START + timedelta(days=random.randrange(DAYS))


def login_dt(user):
    """A timestamp drawn from that user's normal working-hours distribution."""
    _, mean, sd = USERS[user]
    while True:
        m = int(random.gauss(mean, sd))
        if 0 <= m < 1440:
            break
    d = rand_day()
    return d.replace(hour=m // 60, minute=m % 60, second=random.randrange(60))


def weighted(d):
    return random.choices(list(d), weights=list(d.values()))[0]


lines = []          # (datetime, text)


def add(dt, text):
    lines.append((dt, f"{stamp(dt)} server {text}"))


# ---------------------------------------------------------------- background
N_ACC, N_FAIL = 1300, 300
N_CLOSED, N_DISC, N_SUDO, N_INVALID = 100, 80, 80, 70

for _ in range(N_ACC):
    u = weighted(ACC_W)
    dt = login_dt(u)
    ip = USERS[u][0]
    if random.random() < 0.01:                      # occasional travel
        ip = random.choice(HOSTILE)
    add(dt, f"sshd[{pid()}]: Accepted password for {u} from {ip} port {port()} ssh2")

for _ in range(N_FAIL):
    u = weighted(FAIL_W)
    dt = login_dt(u)
    ip = USERS[u][0] if random.random() < 0.45 else random.choice(HOSTILE)
    add(dt, f"sshd[{pid()}]: Failed password for {u} from {ip} port {port()} ssh2")

for _ in range(N_CLOSED):
    dt = rand_day() + timedelta(seconds=random.randrange(86400))
    ip = f"192.168.{random.randint(2, 5)}.{random.randint(1, 254)}"
    add(dt, f"sshd[{pid()}]: Connection closed by {ip}")

for _ in range(N_DISC):
    dt = rand_day() + timedelta(seconds=random.randrange(86400))
    ip = f"192.168.{random.randint(2, 5)}.{random.randint(1, 254)}"
    add(dt, f"sshd[{pid()}]: Disconnected from {ip} port {port()}")

for _ in range(N_SUDO):
    u = random.choice(SUDO_USERS)
    dt = login_dt(u)
    add(dt, f"sudo[{pid()}]: {u} : TTY=pts/{random.randint(0, 2)} ; COMMAND=/bin/ls")

for _ in range(N_INVALID):
    dt = rand_day() + timedelta(seconds=random.randrange(86400))
    add(dt, f"sshd[{pid()}]: Invalid user guest from {random.choice(HOSTILE)}")

# ------------------------------------------------------- planted attack scenes
# 3 brute-force bursts: rapid failures from one hostile IP
# NOTE: dedicated single-use attacker IPs. See fixture 12 in the manifest for
# why a burst from an IP that also appears earlier in the log is not detected.
for day, ip, user, n in [(3, "198.18.7.31", "root", 14),
                         (11, "198.18.44.9", "admin", 9),
                         (22, "198.18.90.204", "john", 20)]:
    base = START + timedelta(days=day, hours=random.randint(1, 4))
    for k in range(n):
        add(base + timedelta(seconds=3 * k),
            f"sshd[{pid()}]: Failed password for {user} from {ip} port {port()} ssh2")

# 2 fail-then-success runs: several failures then a success from the same IP
for day, ip, user, n in [(7, "198.18.12.60", "admin", 6),
                         (18, "198.18.31.118", "deploy", 17)]:
    base = START + timedelta(days=day, hours=2)
    for k in range(n):
        add(base + timedelta(seconds=4 * k),
            f"sshd[{pid()}]: Failed password for {user} from {ip} port {port()} ssh2")
    add(base + timedelta(seconds=4 * n + 5),
        f"sshd[{pid()}]: Accepted password for {user} from {ip} port {port()} ssh2")

# 2 impossible-travel events: same user, 3+ distinct IPs within minutes
for day, user, ips in [(9, "priya", ["192.168.1.50", "185.220.101.5", "45.33.32.156"]),
                       (25, "sarah", ["192.168.1.30", "103.21.244.0", "91.108.4.10", "77.88.55.80"])]:
    base = START + timedelta(days=day, hours=15)
    for k, ip in enumerate(ips):
        add(base + timedelta(minutes=2 * k),
            f"sshd[{pid()}]: Accepted password for {user} from {ip} port {port()} ssh2")

# 4 unusual-hour logins: successful, far outside that user's normal window
for day, user, hour in [(5, "john", 3), (14, "deploy", 4),
                        (20, "mike", 2), (27, "admin", 23)]:
    d = START + timedelta(days=day)
    dt = d.replace(hour=hour, minute=random.randrange(60), second=random.randrange(60))
    add(dt, f"sshd[{pid()}]: Accepted password for {user} from {USERS[user][0]} port {port()} ssh2")

# ------------------------------------------------------------------- assemble
lines.sort(key=lambda t: t[0])
lines = lines[:TARGET] if len(lines) > TARGET else lines

with open("/home/claude/out/auth_general_2000.log", "w") as fh:
    fh.write("\n".join(t for _, t in lines) + "\n")

print("lines written:", len(lines))
print("range:", lines[0][1][:15], "->", lines[-1][1][:15])
