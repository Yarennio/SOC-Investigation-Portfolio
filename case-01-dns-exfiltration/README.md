# DNS Exfiltration Investigation

> [!NOTE]
> **Lab Context:** This investigation was conducted in a TryHackMe simulated SOC environment using Microsoft Sentinel. All hosts, users, domains, and other entities shown in this case belong to the lab environment.

## Scenario

Suspicious activity was identified on the Windows host `win-3450`, associated with the user `michael.ascot`.

The investigation revealed a sequence of PowerShell-driven actions involving a mapped network share, file staging with `Robocopy.exe`, and repeated `nslookup.exe` executions querying changing subdomains of `haz4rdw4re.io`.

The overall behavior was investigated as potential DNS-based data exfiltration activity.

## Initial Alert

The initial alert identified an uncommon parent-child process relationship involving `powershell.exe` and `nslookup.exe` on the host `win-3450`.

Further review showed repeated child process activity associated with the same PowerShell parent process, which required deeper investigation.

## Investigation

The investigation began by reviewing the PowerShell process and identifying its related child processes on `win-3450`.

The PowerShell process with PID `3728` was observed mapping the network share `\\FILESRV-01\SSF-FinancialRecords` to drive `Z:` using `net.exe`.

Further process correlation showed that the same PowerShell process spawned `Robocopy.exe` with PID `8356`, which was associated with copying data from the mapped network share into the local directory:

`C:\Users\michael.ascot\Downloads\exfiltration\`

The same PowerShell parent process later spawned multiple `nslookup.exe` processes. These processes queried changing and encoded-looking subdomains of `haz4rdw4re.io`.

The repeated DNS queries, combined with the earlier file staging activity, were investigated as part of the same attack chain.

## Evidence

The following evidence supported the investigation:

- PowerShell with PID `3728` was identified as the parent process for multiple related activities.
- `net.exe` was used to map `\\FILESRV-01\SSF-FinancialRecords` to the `Z:` drive.
- `Robocopy.exe` with PID `8356` was spawned by the same PowerShell process and was associated with copying data into `C:\Users\michael.ascot\Downloads\exfiltration\`.
- Multiple `nslookup.exe` processes were spawned by the same PowerShell parent process.
- The DNS queries contained changing, long, and encoded-looking subdomains of `haz4rdw4re.io`.
- The repeated DNS activity occurred in the same investigation context as the earlier file staging activity.
- The mapped `Z:` drive was later disconnected using `net.exe use Z: /delete`, which removed the drive mapping but did not delete previously copied files.

### Evidence 1 – Suspicious DNS Query

<p align="center">
  <img width="608" height="382" alt="Suspicious nslookup event"
       src="https://github.com/user-attachments/assets/db9ddd85-1afa-4ed1-9d28-ef25cb997f07" />
</p>

<p align="center">
  <em>Figure 1 – A single <code>nslookup.exe</code> process spawned by PowerShell PID <code>3728</code>, querying an encoded-looking subdomain of <code>haz4rdw4re.io</code> from the <code>exfiltration</code> working directory.</em>
</p>

### Evidence 2 – Repeated nslookup Activity

<p align="center">
  <img width="1119" height="370" alt="Multiple nslookup processes"
       src="https://github.com/user-attachments/assets/06825035-d6ac-4d8c-ae7e-87e6751a7af9" />
</p>

<p align="center">
  <em>Figure 2 – Multiple <code>nslookup.exe</code> processes spawned by the same PowerShell parent process, each using different process IDs and querying changing subdomains.</em>
</p>

### Evidence 3 – Network Share and DNS Correlation

<p align="center">
  <img width="658" height="371" alt="Network share and DNS activity"
       src="https://github.com/user-attachments/assets/4c0791b9-2467-4102-9935-51fab0911f4b" />
</p>

<p align="center">
  <em>Figure 3 – <code>net.exe</code> was used to map and later disconnect the <code>Z:</code> network drive, while repeated <code>nslookup.exe</code> activity was observed in the same investigation context.</em>
</p>

## Indicators & Entities

- **Affected Host:** `win-3450`
- **Affected User:** `michael.ascot`
- **Suspicious Domain:** `haz4rdw4re.io`
- **PowerShell Parent PID:** `3728`
- **Robocopy PID:** `8356`
- **Network Share:** `\\FILESRV-01\SSF-FinancialRecords`
- **Staging Directory:** `C:\Users\michael.ascot\Downloads\exfiltration\`

## Attack Chain

The observed activity followed the sequence below:

`PowerShell (PID 3728)`  
→ `net.exe` mapped `\\FILESRV-01\SSF-FinancialRecords` to `Z:`  
→ `Robocopy.exe` staged data into `C:\Users\michael.ascot\Downloads\exfiltration\`  
→ Multiple `nslookup.exe` processes were spawned  
→ Changing and encoded-looking subdomains of `haz4rdw4re.io` were queried  
→ The `Z:` drive mapping was removed using `net.exe use Z: /delete`

This sequence was consistent with data collection, staging, and DNS-based exfiltration activity.

## Analysis

The activity was considered suspicious because multiple legitimate Windows tools were used together in a sequence consistent with data staging and exfiltration.

The mapped network share was named `SSF-FinancialRecords`, and `Robocopy.exe` was used to stage data into a local directory named `exfiltration`.

The same PowerShell parent process then spawned multiple `nslookup.exe` processes that queried changing and encoded-looking subdomains of `haz4rdw4re.io`.

A single `nslookup.exe` execution could be legitimate, but the repeated DNS queries, changing subdomains, shared PowerShell parent process, and earlier file staging activity significantly increased the likelihood of malicious behavior.

When correlated together, the evidence was consistent with DNS-based data exfiltration rather than normal administrative activity.

## Verdict

🟢 **True Positive**

The alert was classified as a True Positive because the correlated evidence showed a sequence of activity consistent with data staging and DNS-based data exfiltration.

The repeated `nslookup.exe` executions, changing encoded-looking subdomains, shared PowerShell parent process, and prior access to the `SSF-FinancialRecords` network share strongly supported malicious activity.

> [!TIP]
> **Key Takeaway:** The investigation demonstrated how individually legitimate tools can become suspicious when their behavior is correlated across process activity, file staging, network share access, and DNS communication.

## Remediation

Recommended remediation actions include:

- Isolate the affected host `win-3450` from the network to prevent further malicious activity.
- Block the domain `haz4rdw4re.io` and related indicators at the appropriate security controls.
- Review and terminate suspicious PowerShell and `nslookup.exe` activity associated with the incident.
- Investigate the contents of `C:\Users\michael.ascot\Downloads\exfiltration\` to determine what data was staged.
- Review access to `\\FILESRV-01\SSF-FinancialRecords` and determine whether sensitive files were accessed or copied.
- Reset or review credentials associated with the affected user if account compromise is suspected.
- Perform additional endpoint and network investigation to identify persistence, lateral movement, or other related malicious activity.

## Lessons Learned

This investigation reinforced several important SOC analysis principles:

- Legitimate administrative tools such as PowerShell, `net.exe`, `Robocopy.exe`, and `nslookup.exe` can be abused as part of a malicious attack chain.
- A single suspicious event is often not enough to determine intent; correlating multiple related activities provides stronger context.
- Parent-child process relationships and a shared parent PID can help connect separate events to the same activity chain.
- Repeated DNS queries with changing and encoded-looking subdomains can be a strong indicator of DNS-based data exfiltration.
- File staging activity should be investigated together with subsequent network behavior to understand the full sequence of an incident.
- Removing a mapped drive with `net.exe use Z: /delete` only removes the mapping and does not delete previously copied files.
- Investigation decisions should be based on correlated evidence rather than a single tool, alert, or observable.
