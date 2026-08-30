# PowerView Reconnaissance Investigation

> [!NOTE]
> **Lab Context:** This investigation was conducted in a TryHackMe simulated SOC environment using Microsoft Sentinel. All hosts, users, processes, scripts, and other entities shown in this case belong to the lab environment.

## Scenario

Suspicious PowerShell activity was identified on the Windows host `win-3450`, associated with the user `michael.ascot`.

The investigation revealed that a PowerShell process created `PowerView.ps1`, a PowerShell-based tool commonly associated with Active Directory reconnaissance and discovery.

Further review showed that the same PowerShell parent process spawned several Windows discovery utilities, including `systeminfo.exe`, `whoami.exe`, and `net.exe`.

The activity was investigated as potential reconnaissance behavior and was correlated with previously identified malicious activity on the same host.

## Initial Alert

The initial alert indicated suspicious PowerShell-related activity on the host `win-3450`.

Further review identified the creation of `PowerView.ps1` in the user’s Downloads directory and showed that the related PowerShell process was associated with additional discovery activity.

Because PowerView can be used for Active Directory reconnaissance, the alert required further investigation to determine whether the activity was legitimate or malicious.

## Investigation

The investigation focused on the PowerShell process associated with the alert and the activity it generated on `win-3450`.

A PowerShell process with PID `9060` was identified as the process responsible for creating `PowerView.ps1` at the following path:

`C:\Users\michael.ascot\Downloads\PowerView.ps1`

Further process review showed that the same PowerShell parent process spawned several Windows discovery utilities, including:

- `systeminfo.exe`
- `whoami.exe`
- `net.exe`

These commands were used to collect information about the host, the current user context, and the surrounding environment.

The activity was then correlated with previously confirmed malicious behavior on the same host, which increased the likelihood that the PowerView-related activity was part of the same broader attack chain.

## Evidence

The following evidence supported the investigation:

- A PowerShell process with PID `9060` was identified as the parent process associated with the suspicious activity.
- `PowerView.ps1` was created at `C:\Users\michael.ascot\Downloads\PowerView.ps1`.
- The same PowerShell parent process spawned `systeminfo.exe`, `whoami.exe`, and `net.exe`.
- These child processes are commonly used to collect system, user, and environment information.
- The activity occurred on the same host where previously confirmed malicious behavior had already been identified.
- The combination of PowerView script creation and multiple discovery commands strengthened the assessment that the activity was reconnaissance-related.

### Evidence 1 – PowerView Script Creation

<p align="center">
  <img
    width="663"
    height="338"
    alt="PowerView script creation"
    src="https://github.com/user-attachments/assets/cbed3896-632e-483c-8e57-fcff59845580"
  />
</p>

<p align="center">
  <em>
    Figure 1 – PowerShell PID <code>9060</code> created <code>PowerView.ps1</code> in the user’s Downloads directory on <code>win-3450</code>.
  </em>
</p>

### Evidence 2 – Discovery Process Chain

<p align="center">
  <img
    width="1191"
    height="271"
    alt="PowerShell discovery child processes"
    src="https://github.com/user-attachments/assets/68a51bf7-522d-46f9-9625-854a2a879773"
  />
</p>

<p align="center">
  <em>
    Figure 2 – The same PowerShell parent process, PID <code>9060</code>, spawned <code>systeminfo.exe</code>, <code>whoami.exe</code>, and <code>net.exe</code>, indicating coordinated discovery activity.
  </em>
</p>

## Indicators & Entities

- **Affected Host:** `win-3450`
- **Affected User:** `michael.ascot`
- **PowerShell Parent PID:** `9060`
- **Suspicious Script:** `PowerView.ps1`
- **Script Path:** `C:\Users\michael.ascot\Downloads\PowerView.ps1`
- **Related Discovery Processes:** `systeminfo.exe`, `whoami.exe`, `net.exe`
- **Activity Type:** Reconnaissance / Discovery

## Attack Chain

The observed activity followed the sequence below:

`PowerShell (PID 9060)`  
→ `PowerView.ps1` was created in the user’s Downloads directory  
→ `systeminfo.exe`, `whoami.exe`, and `net.exe` were spawned for discovery activity  
→ Host, user, and environment information was collected  
→ The activity was correlated with previously confirmed malicious behavior on the same host

This sequence was consistent with reconnaissance and discovery activity within the affected environment.

## Analysis

The activity was considered suspicious because PowerView and several native Windows discovery utilities were observed together under the same PowerShell parent process.

`PowerView.ps1` is commonly associated with Active Directory reconnaissance, while `systeminfo.exe`, `whoami.exe`, and `net.exe` can be used to collect information about the host, current user context, and surrounding environment.

Individually, these tools may be used for legitimate administrative purposes. However, the combination of PowerView script creation, multiple discovery processes, a shared PowerShell parent PID, and previously confirmed malicious activity on the same host significantly increased the likelihood that the behavior was part of an attacker-led reconnaissance phase.

When correlated together, the evidence was more consistent with malicious discovery activity than normal administrative behavior.

## Verdict

🟢 **True Positive**

The alert was classified as a True Positive because the correlated evidence showed a reconnaissance and discovery pattern associated with suspicious PowerShell activity.

The presence and creation of `PowerView.ps1`, combined with discovery utilities such as `systeminfo.exe`, `whoami.exe`, and `net.exe`, all associated with the same PowerShell parent process, strongly supported malicious reconnaissance activity.

The previously confirmed malicious behavior on the same host further increased confidence that this activity was part of the same broader attack chain.

> [!TIP]
> **Key Takeaway:** Legitimate discovery tools can become strong indicators of malicious reconnaissance when they are executed together under the same suspicious parent process and correlated with prior malicious activity.

## Remediation

Recommended remediation actions include:

- Isolate the affected host `win-3450` to prevent further malicious activity while the incident is investigated.
- Review and terminate suspicious PowerShell activity associated with PID `9060`.
- Remove or quarantine `PowerView.ps1` if it is not authorized for legitimate administrative use.
- Investigate the user account `michael.ascot` for signs of credential compromise or unauthorized access.
- Review related process and authentication activity to determine whether additional discovery, persistence, or lateral movement occurred.
- Search for similar PowerView or discovery activity across other hosts to determine whether the behavior is isolated or part of a broader incident.
- Restrict or monitor unauthorized PowerShell and reconnaissance tooling where appropriate.

## Lessons Learned

This investigation reinforced several important SOC analysis principles:

- PowerView is a legitimate security and administration tool, but its use can be suspicious when it appears in an unexpected context.
- Native Windows utilities such as `systeminfo.exe`, `whoami.exe`, and `net.exe` should not be judged as malicious based on their names alone.
- Parent-child process relationships and a shared parent PID can help connect multiple discovery activities to the same source process.
- Reconnaissance is often identified by a pattern of related information-gathering actions rather than a single command.
- Previous malicious activity on the same host can significantly change the context and confidence of a new alert.
- Investigation decisions should be based on correlated evidence, process context, and behavior rather than isolated observables.
- Discovery activity should trigger additional checks for persistence, credential compromise, and lateral movement.
