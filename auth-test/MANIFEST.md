# auth-prog test logs

Two things here:

- `auth_general_2000.log` — 2000 lines, statistically similar to the original, for general regression testing.
- `fixtures/` — 18 small logs, each aimed at one specific bug.

Everything below was produced by running your current `src/` (post-`ruff --fix`) against
each file. "Actual" is observed, not predicted.

---

## 1. General log — `auth_general_2000.log`

Same six line shapes as the original, same seven users, same home-IP mapping,
per-user login-hour means and sigmas copied from your data. Spans **Feb 01 – Mar 02
2026** rather than January, so month rollover is exercised too.

| | original | generated |
|---|---|---|
| Accepted | 1149 | 1309 |
| Failed | 297 | 366 |
| Connection closed | 85 | 97 |
| sudo | 74 | 80 |
| Disconnected | 75 | 79 |
| Invalid user | 64 | 69 |
| lines | 1743 | 2000 |

Planted scenarios so all four rules fire: 3 brute-force bursts, 2 fail-then-success
runs, 2 impossible-travel events, 4 unusual-hour logins.

Current behaviour: **1823 parsed rows** (1823, not 2000, because
`Connection closed` and `sudo` lines are dropped — but `Disconnected` lines are not,
see `p01`), then bfd=20, uhd=6, mid=1, fsd=11.

The attacker IPs in the planted bursts are deliberately single-use (198.18.x.x). If
you reuse an IP that already appears earlier in the log, the burst is not detected at
all — that is bug `r04`, found while building this file.

---

## 2. Bug fixtures

### Parser

| File | Targets | Correct behaviour | Actual |
|---|---|---|---|
| `p01_disconnected_leak.log` | `parser.py:32` | 3 `Disconnected`/`Connection closed` lines dropped, 1 row for alice | **3 rows**; users are `['Disconnected', 'alice']` — the literal string `Disconnected` becomes a username |
| `p02_timestamp_unbound.log` | `parser.py:17-20` | line without a timestamp skipped or rejected | **`UnboundLocalError: cannot access local variable 'timestamp_dt'`** |
| `p03_timestamp_stale.log` | `parser.py:17-20` | 3 rows with 3 distinct timestamps | 3 rows, but row 2 silently reuses row 1's timestamp. All three rules then die with `AttributeError` on a `None` status |
| `p04_none_fields.log` | `parser.py:42,45` | malformed lines rejected | rows with `user=None`, `ip=None`, `status=None`; every rule raises `TypeError` on the sort |
| `p05_process_regex.log` | `parser.py:35` | `sudoedit` treated like `sudo` | `\w{4}` reads the four characters before `[`, so `sudoedit[2001]` yields process `edit` and is **not** skipped; it lands in the data as a junk row. `su[…]` and `cron[…]` never match the pattern at all |
| `p06_sudo_field_dead.log` | `parser.py:54` | sudo activity captured, or the key removed | 2 sudo lines dropped, 1 row returned, `sudo` key is `None` |
| `p07_empty.log` | `main.py:12-17` | empty input handled | all four rules raise `IndexError: list index out of range` |

### Brute-force rule

| File | Targets | Correct behaviour | Actual |
|---|---|---|---|
| `r01_num_fail_threshold.log` | `rules.py:5` and `:9` | whichever threshold you intended | 4 rapid failures produce a flag, proving line 9's `NUM_FAIL = 4` is live and line 5's `= 5` is dead |
| `r02_accepted_seeded.log` | `rules.py:21-26` | 3 failures, below threshold, no flag | **flagged.** The first entry is an *accepted* login for `10.0.0.1` and gets counted, because the status check at line 62 is not applied to the seed |
| `r03_offbyone_count.log` | `rules.py:32,36` | 3 failures inside 60s, below threshold of 4 | **flagged, reporting `count: 4`** when only 3 failures fall in the window |
| `r04a_burst_first.log` | control | flag | flag |
| `r04b_burst_last.log` | `rules.py:33` | same flag — identical burst, different position | **no flag.** Once `sw_l` catches up to `sw_r` the `sw_r > sw_l` guard ends the loop permanently, so only failures at the *start* of an IP's timeline are ever examined |

`r04a`/`r04b` contain the same five-failure burst and the same five scattered
failures. The only difference is whether the burst comes first or last.

### Unusual-hour and multi-IP rules

| File | Targets | Correct behaviour | Actual |
|---|---|---|---|
| `r06a_last_user_kept.log` | control | zoe's 03:00 login flagged | 1 uhd flag |
| `r06b_last_user_dropped.log` | `rules.py:90,95` | same flag | **no flag.** The sentinel is `sorted_data[0]`, and line 95 skips anything whose status is not `accepted`. Changing the first entry from Accepted to Failed silently discards the entire last user group. `multi_ip_detection` has the same defect at line 139 |
| `r07_uhd_self_masking.log` | `rules.py:107-116` | alice's 03:00 login flagged | **no flag.** The outlier sits inside its own mean and stdev: with it, sd = 180 min and 3σ = 540 min, so the lower bound goes negative and is clamped to 0 by line 110. Without it, sd = 10 min and the bound is 08:30 — the login would be flagged |
| `r08_multi_ip_window.log` | positive control | 1 mid flag | 1 mid flag |

### Fail-then-success rule

| File | Targets | Correct behaviour | Actual |
|---|---|---|---|
| `r09_fsd_no_reset.log` | `rules.py:212-221` | the legitimate success from 192.168.1.10 resets the counter, so only 1 failure precedes the attacker's success | **flag reports `count: 5`.** A success from an IP not in `ip_list` resets neither `num_fail` nor `ip_list`, so failures accumulate straight through it |

### Reporter

| File | Targets | Correct behaviour | Actual |
|---|---|---|---|
| `rp01_single_flag.log` | `reporter.py:148` | a one-flag report | `summary_report` raises `StatisticsError: stdev requires at least two data points` |

---

## 3. Corrections to the earlier bug list

Three items I gave you did not survive testing. Ignore them.

**"All four rules mutate the caller's list."** Wrong. `sorted()` returns a new list,
so the sentinel is appended to a copy. Parsed-row count before and after running all
four rules: 4 and 4. The `.copy()` at line 27 versus the bare reference at lines 90,
139 and 196 is still an inconsistency, but it has no observable effect.

**"`sorted()` by ip sorts IPs as strings"** — true, and it does raise on a `None` ip
(covered by `p04`), but the ordering itself is harmless. String sort still groups
identical IPs together, which is all the rule needs. `10.0.0.5` sorting before
`9.9.9.9` changes nothing.

**"`NUM_FAIL` used as a group-size gate at `rules.py:204`."** Cosmetic only. Any
detectable case needs at least 4 failures plus a success — 5 events — so a gate of 4
can never exclude one. Worth renaming, not worth a test.

## 4. New bug, not in the original list

`rules.py:33` — the `sw_r > sw_l` loop guard. See `r04a`/`r04b` above. This is more
consequential than most of the list: it means brute-force detection only ever
inspects the beginning of each IP's failure timeline. Your original `auth.log` hides
it because the planted bursts happen to be the earliest events for their IPs.
