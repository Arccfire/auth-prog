"""Write one small, purpose-built log per bug, then run the current code
against each and record what actually happens.
"""

import os
import sys
import traceback

OUT = "/home/claude/out/fixtures"
os.makedirs(OUT, exist_ok=True)
sys.path.insert(0, "/home/claude/src")

PID = 1000


def L(ts, msg):
    global PID
    PID += 1
    return f"{ts} server sshd[{PID}]: {msg}"


def acc(ts, user, ip, port=22222):
    return L(ts, f"Accepted password for {user} from {ip} port {port} ssh2")


def fail(ts, user, ip, port=33333):
    return L(ts, f"Failed password for {user} from {ip} port {port} ssh2")


F = {}   # name -> (purpose, lines)


def fx(name, purpose, lines):
    F[name] = (purpose, lines)


# ---------------------------------------------------------------- parser
fx("p01_disconnected_leak.log",
   'parser.py:32 tests for "disconnection"; the log says "Disconnected"',
   [L("Mar 01 09:00:00", "Disconnected from 192.168.1.10 port 40001"),
    L("Mar 01 09:00:10", "Disconnected from 192.168.1.20 port 40002"),
    L("Mar 01 09:00:20", "Connection closed by 192.168.1.30"),
    acc("Mar 01 09:00:30", "alice", "192.168.1.10")])

fx("p02_timestamp_unbound.log",
   "parser.py:17-20 first line has no timestamp, timestamp_dt never bound",
   ["kernel: unrelated line with no timestamp at all",
    acc("Mar 01 09:00:00", "alice", "192.168.1.10")])

fx("p03_timestamp_stale.log",
   "parser.py:17-20 second line has no timestamp, reuses line 1's value",
   [acc("Mar 01 09:00:00", "alice", "192.168.1.10"),
    "sshd: Accepted password for bob from 192.168.1.20 port 1 ssh2",
    acc("Mar 01 18:30:00", "carol", "192.168.1.30")])

fx("p04_none_fields.log",
   "parser.py:42,45 walrus assigns None on non-match; None reaches the rules",
   [acc("Mar 01 09:00:00", "alice", "192.168.1.10"),
    L("Mar 01 09:05:00", "Failed password for bob port 999 ssh2"),
    "Mar 01 09:10:00 server kernel audit event without a bracket-colon"])

fx("p05_process_regex.log",
   r"parser.py:35 \w{4} hard-codes a 4-character process name",
   ["Mar 01 09:00:00 server sudoedit[2001]: alice : TTY=pts/0 ; COMMAND=/bin/vi",
    "Mar 01 09:01:00 server su[2002]: Accepted password for bob from 192.168.1.20 port 1 ssh2",
    "Mar 01 09:02:00 server cron[2003]: Accepted password for carol from 192.168.1.30 port 1 ssh2",
    "Mar 01 09:03:00 server sudo[2004]: dave : TTY=pts/0 ; COMMAND=/bin/ls"])

fx("p06_sudo_field_dead.log",
   'parser.py:54 the "sudo" key is hard-coded None for every row',
   ["Mar 01 09:00:00 server sudo[3001]: alice : TTY=pts/0 ; COMMAND=/bin/ls",
    "Mar 01 09:01:00 server sudo[3002]: bob : TTY=pts/0 ; COMMAND=/usr/bin/id",
    acc("Mar 01 09:02:00", "alice", "192.168.1.10")])

fx("p07_empty.log",
   "empty input; every rule indexes sorted_data[0]",
   [])

# --------------------------------------------------------- brute force rule
fx("r01_num_fail_threshold.log",
   "rules.py:5 vs 9 NUM_FAIL defined twice (5 then 4); 4 rapid failures fire",
   [fail("Mar 01 02:00:00", "alice", "203.0.113.9"),
    fail("Mar 01 02:00:05", "alice", "203.0.113.9"),
    fail("Mar 01 02:00:10", "alice", "203.0.113.9"),
    fail("Mar 01 02:00:15", "alice", "203.0.113.9"),
    acc("Mar 01 03:00:00", "bob", "203.0.113.99")])

fx("r02_accepted_seeded.log",
   "rules.py:21-26 first element is seeded without the status check at line 62",
   [acc("Mar 01 02:00:00", "alice", "10.0.0.1"),          # lowest IP string, ACCEPTED
    fail("Mar 01 02:00:04", "alice", "10.0.0.1"),
    fail("Mar 01 02:00:08", "alice", "10.0.0.1"),
    fail("Mar 01 02:00:12", "alice", "10.0.0.1"),
    acc("Mar 01 05:00:00", "bob", "10.0.0.9")])

fx("r03_offbyone_count.log",
   "rules.py:32,36 ts_num counts one more than the window actually holds",
   [fail("Mar 01 02:00:00", "alice", "203.0.113.9"),      # 3 inside 60s
    fail("Mar 01 02:00:03", "alice", "203.0.113.9"),
    fail("Mar 01 02:00:06", "alice", "203.0.113.9"),
    fail("Mar 01 06:00:00", "alice", "203.0.113.9"),      # 2 far away
    fail("Mar 01 12:00:00", "alice", "203.0.113.9"),
    acc("Mar 01 13:00:00", "bob", "203.0.113.99")])

_scatter_a = [fail(f"Mar 0{d} 08:00:00", "alice", "203.0.113.9") for d in range(2, 7)]
fx("r04a_burst_first.log",
   "rules.py:33 control: identical burst placed FIRST in that IP's timeline",
   [fail("Mar 01 02:00:00", "alice", "203.0.113.9"),
    fail("Mar 01 02:00:03", "alice", "203.0.113.9"),
    fail("Mar 01 02:00:06", "alice", "203.0.113.9"),
    fail("Mar 01 02:00:09", "alice", "203.0.113.9"),
    fail("Mar 01 02:00:12", "alice", "203.0.113.9")]
   + _scatter_a + [acc("Mar 08 09:00:00", "bob", "203.0.113.99")])

fx("r04b_burst_last.log",
   "rules.py:33 same burst placed LAST; loop exits once sw_l reaches sw_r",
   _scatter_a
   + [fail("Mar 07 02:00:00", "alice", "203.0.113.9"),
      fail("Mar 07 02:00:03", "alice", "203.0.113.9"),
      fail("Mar 07 02:00:06", "alice", "203.0.113.9"),
      fail("Mar 07 02:00:09", "alice", "203.0.113.9"),
      fail("Mar 07 02:00:12", "alice", "203.0.113.9")]
   + [acc("Mar 08 09:00:00", "bob", "203.0.113.99")])

# -------------------------------------------- dropped last user group (uhd/mid)
_zoe = ([acc(f"Mar 0{d} 09:0{m}:00", "zoe", "192.168.1.90")
         for d in range(1, 5) for m in range(3)]
        + [acc("Mar 05 03:00:00", "zoe", "192.168.1.90")])       # clear outlier

fx("r06a_last_user_kept.log",
   "rules.py:90,95 control: first entry after the user sort is ACCEPTED",
   [acc("Mar 01 09:00:00", "alice", "192.168.1.10"),
    acc("Mar 02 09:01:00", "alice", "192.168.1.10"),
    acc("Mar 03 09:02:00", "alice", "192.168.1.10")] + _zoe)

fx("r06b_last_user_dropped.log",
   "rules.py:90,95 same data, first entry FAILED, so the sentinel is skipped",
   [fail("Mar 01 09:00:00", "alice", "192.168.1.10"),
    acc("Mar 02 09:01:00", "alice", "192.168.1.10"),
    acc("Mar 03 09:02:00", "alice", "192.168.1.10"),
    acc("Mar 04 09:03:00", "alice", "192.168.1.10")] + _zoe)

fx("r07_uhd_self_masking.log",
   "rules.py:107-116 the outlier is inside its own mean and stdev",
   [acc("Mar 01 09:00:00", "alice", "192.168.1.10"),
    acc("Mar 02 09:10:00", "alice", "192.168.1.10"),
    acc("Mar 03 08:50:00", "alice", "192.168.1.10"),
    acc("Mar 04 03:00:00", "alice", "192.168.1.10"),      # 6 hours early
    acc("Mar 05 09:00:00", "zoe", "192.168.1.90"),
    acc("Mar 06 09:00:00", "zoe", "192.168.1.90"),
    acc("Mar 07 09:00:00", "zoe", "192.168.1.90")])

# ------------------------------------------------------- multi-ip rule
fx("r08_multi_ip_window.log",
   "positive control for multi_ip_detection; also exercises rules.py:161",
   [acc("Mar 01 09:00:00", "alice", "192.168.1.10"),
    acc("Mar 01 09:03:00", "alice", "203.0.113.7"),
    acc("Mar 01 09:06:00", "alice", "198.51.100.8"),
    acc("Mar 01 09:09:00", "alice", "45.33.32.156"),
    acc("Mar 02 09:00:00", "zoe", "192.168.1.90"),
    acc("Mar 03 09:00:00", "zoe", "192.168.1.90"),
    acc("Mar 04 09:00:00", "zoe", "192.168.1.90")])

# ------------------------------------------------------- fail-then-success rule
fx("r09_fsd_no_reset.log",
   "rules.py:212-221 a success from an unrelated IP resets neither counter",
   [fail("Mar 01 02:00:00", "alice", "203.0.113.9"),
    fail("Mar 01 02:01:00", "alice", "203.0.113.9"),
    fail("Mar 01 02:02:00", "alice", "203.0.113.9"),
    fail("Mar 01 02:03:00", "alice", "203.0.113.9"),
    acc("Mar 01 02:04:00", "alice", "192.168.1.10"),      # legitimate, different IP
    fail("Mar 01 02:05:00", "alice", "203.0.113.9"),
    acc("Mar 01 02:06:00", "alice", "203.0.113.9"),       # attacker succeeds
    acc("Mar 02 09:00:00", "zoe", "192.168.1.90")])

# ------------------------------------------------------------------- reporter
fx("rp01_single_flag.log",
   "reporter.py:148 st.stdev needs two points; this log yields exactly one flag",
   [fail("Mar 01 02:00:00", "alice", "203.0.113.9"),
    fail("Mar 01 02:00:03", "alice", "203.0.113.9"),
    fail("Mar 01 02:00:06", "alice", "203.0.113.9"),
    fail("Mar 01 02:00:09", "alice", "203.0.113.9"),
    acc("Mar 01 09:00:00", "bob", "203.0.113.99")])

# ------------------------------------------------------------------- write
for name, (purpose, lines) in F.items():
    with open(os.path.join(OUT, name), "w") as fh:
        fh.write("\n".join(lines) + ("\n" if lines else ""))

# ------------------------------------------------------------------- verify
import importlib  # noqa: E402
parser = importlib.import_module("parser")
rules = importlib.import_module("rules")
reporter = importlib.import_module("reporter")

RULES = [("bfd", rules.rule_brute_force), ("uhd", rules.unusual_hour_detection),
         ("mid", rules.multi_ip_detection), ("fsd", rules.fail_success_detection)]

print(f"{'fixture':32s} {'rows':>5s}  outcome")
print("-" * 100)
for name in F:
    path = os.path.join(OUT, name)
    try:
        d = parser.parse_log(path)
    except Exception as e:
        print(f"{name:32s} {'--':>5s}  parse_log raises {type(e).__name__}: {e}")
        continue
    bits = []
    for tag, fn in RULES:
        try:
            n = len(fn(list(d)))
            if n:
                bits.append(f"{tag}={n}")
        except Exception as e:
            bits.append(f"{tag}!{type(e).__name__}")
    users = sorted({str(x["user"]) for x in d})
    print(f"{name:32s} {len(d):5d}  users={users}  {' '.join(bits) or 'no flags'}")
