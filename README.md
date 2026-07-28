# Home SIEM Lab (Wazuh)

## What this demonstrates

Building and validating a real custom SIEM detection rule — not just installing Wazuh, but proving a rule actually catches the attack it's designed for, debugging it when it silently doesn't, and confirming the fix with a genuine live attack before calling it done.

## Environment

- **Wazuh manager, indexer, and dashboard:** self-hosted, single-node, on an Ubuntu Server VM
- **Monitored host:** the same VM, via Wazuh's built-in local self-monitoring (agent ID `000`) — no separate agent install needed or possible on a manager host, by design
- **Attacker:** Kali Linux VM, same isolated lab network
- **Attack tool:** Hydra, SSH credential brute-forcing

## Process

### 1. Confirm the manager monitors itself

Wazuh managers automatically include a built-in local agent (ID `000`) that reads the host's own logs — a standalone `wazuh-agent` package cannot be installed alongside `wazuh-manager` on the same machine; the package manager itself blocks it as a conflict, since it isn't necessary.

```bash
sudo /var/ossec/bin/agent_control -l
```
Confirmed: `ID: 000, Name: ubuntu-target (server), IP: 127.0.0.1, Active/Local`

### 2. Add the authentication log as a monitored source

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/auth.log</location>
</localfile>
```
Added to `/var/ossec/etc/ossec.conf`, alongside the manager's existing default sources.

### 3. Write a custom detection rule for SSH brute-force attempts

```xml
<rule id="100010" level="10" frequency="4" timeframe="120">
  <if_matched_sid>5760</if_matched_sid>
  <same_source_ip />
  <description>Multiple SSH authentication failures from same source - possible brute force (T1110)</description>
  <mitre>
    <id>T1110</id>
  </mitre>
</rule>
```

This rule escalates repeated SSH authentication failures from the same source IP into a labeled brute-force alert, mapped to MITRE ATT&CK technique **T1110 (Brute Force)**.

### 4. Debug it — the rule didn't fire on the first attempt

A live Hydra run produced 206 alert hits, but none of them were the custom rule — they were a different, unrelated built-in Wazuh rule. Rather than assume the rule was broken and guess at a fix, it was validated directly with `wazuh-logtest` against a known sample log line, which surfaced two real, distinct bugs:

- **Missing `frequency`/`timeframe` attributes.** `<if_matched_sid>` requires these on the `<rule>` tag itself to define a countable time window — without them, the rule has no actual evaluation logic and silently never fires, regardless of how correct everything else looks.
- **Wrong base rule ID.** The rule was written to watch for occurrences of rule `5716`, but `wazuh-logtest` showed this specific log format actually decodes to rule `5760` on this Wazuh version — a one-digit-off assumption that would have made the rule permanently blind, even with the frequency/timeframe fix in place.

### 5. Validate the fix directly, before re-attacking

```bash
sudo /var/ossec/bin/wazuh-logtest
```
The same sample line, submitted four times (matching the `frequency="4"` threshold), correctly fired rule `100010` on the fourth submission — confirmed via the tool's own output, independent of any live network traffic.

### 6. Confirm with a real attack

```bash
hydra -t 4 -l codemane1 -P /usr/share/wordlists/rockyou.txt ssh://192.168.81.130
```
(`-t 4` limits parallel connections — OpenSSH's own `PerSourcePenalties` defense started dropping connections from the attacker under Hydra's default 16-thread setting, a real SSH hardening feature worth noting in its own right.)

Result: rule `100010` fired 23 times against the real attack traffic, correctly attributing the source IP (`192.168.81.128`) and citing MITRE technique T1110.

## Key finding

A detection rule that "looks correct" and a detection rule that actually fires are two different things. Two independent, specific bugs — a missing frequency/timeframe pairing and an incorrect base rule ID — both had to be found and fixed before this rule caught anything, and neither would have been obvious without testing against `wazuh-logtest` first rather than going straight to a live attack. This is the actual discipline behind detection engineering: validate the logic in isolation, then confirm against real traffic — not the other way around.

## Files in this repo

- `wazuh_detection_evidence.json` — the real alert record from the live Hydra-triggered detection, including `firedtimes`, source IP, and MITRE mapping
- `sudo_privesc_detection_evidence.json` — the real alert record from the live privilege-escalation detection (see addendum below)
- `screenshots/` — see below

## Screenshots

![Rule validation via wazuh-logtest](screenshots/rule-validation.png)
![Corrected detection rule configuration](screenshots/local-rules-config.png)
![Live alert in the Wazuh dashboard](screenshots/dashboard-alert.png)
![Sudo/privilege-escalation rule validation](screenshots/sudo-rule-validation.png)
![Updated rules file with both detections](screenshots/local-rules-config-v2.png)
![Live privilege-escalation alert confirmation](screenshots/live-alert-confirmation.png)

## What I'd do differently in production

- Test every custom rule with `wazuh-logtest` as a standing first step, not a fallback after a live test fails — it would have caught both bugs here in minutes instead of after a full attack run.
- Tune Hydra's thread count to stay under whatever SSH rate-limiting is in place *before* the first attempt, rather than discovering the limit via a failed run.

---

## Addendum: A Second Detection Rule — Repeated Failed `sudo`/PAM Authentication (T1548)

### What this adds

A second, independently validated detection rule watching for repeated failed privilege-escalation attempts (`sudo`/PAM authentication failures) — demonstrating that the first rule's validated methodology (write → `wazuh-logtest` → live-fire confirm) is a repeatable process, not a one-off.

### The rule

```xml
<rule id="100011" level="10" frequency="3" timeframe="120">
  <if_matched_sid>5503</if_matched_sid>
  <description>Repeated failed sudo/PAM authentication - possible privilege escalation attempt (T1548)</description>
  <mitre>
    <id>T1548</id>
  </mitre>
</rule>
```

Deliberately does **not** use `<same_source_ip />` — unlike an SSH login, a local `sudo` failure carries no source IP at all, so reusing that tag from the first rule without checking would have silently broken the frequency grouping.

### The debugging arc — a real, multi-layered one

**1. A fabricated test line validated against the wrong rule entirely.** The initial test line used to check `wazuh-logtest` was written by hand to look plausible, rather than pulled from real `auth.log` output. It happened to decode to rule `5404` — a real Wazuh rule, just not the one this system's actual `sudo` failures ever produce. Built and "validated" against it, the new rule would have silently never fired against genuine traffic.

**2. Caught by checking the real log directly, not trusting the synthetic line.** Comparing the fabricated test line against actual `auth.log` output from a real failed-`sudo` attempt showed they didn't match at all. The real line — `pam_unix(sudo:auth): authentication failure; ...` — decodes to a completely different base rule: `5503`.

**3. Removing the wrong rule broke the entire manager.** A `sed`-based deletion intended to remove the rule built against `5404` left an orphaned, empty `<group>...</group>` block behind — valid-looking XML that Wazuh's rule parser correctly rejected (`"Group 'group' without any rule"`), taking the whole `wazuh-manager` service down.

**4. Fixed by inspecting the actual file content, not guessing at the damage.** Viewing the full `local_rules.xml` directly showed the exact empty block; a second, precise deletion removed only that fragment, and the manager came back up clean.

**5. Re-validated against the real log line, then confirmed live.** With the rule correctly built against `5503`, `wazuh-logtest` confirmed it firing on the third submission of the real log line. A genuine live test — three real failed `sudo` authentication attempts — triggered rule `100011` for real, captured in `sudo_privesc_detection_evidence.json`.

### Key finding

Every one of the first rule's lessons (validate before attacking, don't assume a base rule ID) held up as generally correct — but this rule's own process surfaced a further, more subtle version of the same failure mode: a synthetic test input can pass validation while still being validated against the *wrong thing*. The fix isn't "trust `wazuh-logtest`" — it's "trust `wazuh-logtest` run against genuinely real data," which is a meaningfully stricter standard than it first appears.