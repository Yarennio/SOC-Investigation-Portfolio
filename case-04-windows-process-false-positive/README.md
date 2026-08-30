# Windows Process False Positive Investigation

> [!NOTE]
> **Lab Context:** This investigation was conducted in a TryHackMe simulated SOC environment using Microsoft Sentinel. All hosts, users, processes, paths, and other entities shown in this case belong to the lab environment.

## Scenario

A Windows process alert was generated after an uncommon parent-child process relationship was observed on a monitored endpoint.

The alert involved the Windows Service Control Manager process `services.exe` and the Windows Modules Installer process `TrustedInstaller.exe`.

Because unusual parent-child process relationships can sometimes indicate process abuse, execution through system services, or malicious activity, the alert required further investigation before classification.

The investigation focused on validating the process relationship, executable path, surrounding activity, and whether any additional suspicious behavior was present.

## Initial Alert

The initial alert identified an uncommon parent-child process relationship involving:

`services.exe`  
→ `TrustedInstaller.exe`

The system-level process relationship triggered the alert because unusual process chains can sometimes be associated with malicious execution or abuse of legitimate Windows services.

However, the process names alone were not considered sufficient evidence of compromise.

Further investigation was required to determine:

- Whether the executable path was legitimate
- Whether the parent-child relationship was expected
- Whether suspicious command-line activity was present
- Whether additional child processes or related malicious behavior could be identified
- Whether the activity was consistent with normal Windows system operations

## Investigation

The investigation focused on validating the relationship between `services.exe` and `TrustedInstaller.exe`.

`services.exe` is a legitimate Windows system process responsible for managing Windows services.

The child process, `TrustedInstaller.exe`, is associated with the Windows Modules Installer service and is normally involved in Windows updates, component installation, and system maintenance activity.

Process information showed that `TrustedInstaller.exe` was associated with the expected Windows servicing path:

`C:\Windows\servicing\TrustedInstaller.exe`

The executable location was consistent with the legitimate Windows TrustedInstaller service.

A Sysmon Process Create event also recorded `TrustedInstaller.exe` on host `win-3459` with PID `3577` at:

`08/21/2026 14:55:45.419`

Further review of the surrounding process activity did not identify suspicious child processes, unusual execution paths, or additional behavior indicating malicious activity.

The parent-child relationship was therefore evaluated in the context of normal Windows service behavior rather than being classified as malicious based only on the alert.

The investigation considered the following factors:

- Both `services.exe` and `TrustedInstaller.exe` are legitimate Windows system processes
- `TrustedInstaller.exe` was associated with the expected Windows servicing path
- The parent-child relationship was consistent with Windows service management behavior
- No suspicious executable path was identified
- No suspicious command-line behavior was identified
- No suspicious child process activity was observed
- No additional malicious behavior was identified during the available investigation

Based on the available evidence, the activity was consistent with normal Windows system behavior.

## Evidence

The following evidence supported the investigation:

- The alert involved the Windows system processes `services.exe` and `TrustedInstaller.exe`.
- `TrustedInstaller.exe` was associated with the expected Windows servicing location:

  `C:\Windows\servicing\TrustedInstaller.exe`

- A Sysmon Process Create event recorded `TrustedInstaller.exe` on host `win-3459`.
- The observed `TrustedInstaller.exe` process used PID `3577`.
- The process creation event occurred at `08/21/2026 14:55:45.419`.
- The executable path and surrounding process context were consistent with legitimate Windows servicing activity.
- No suspicious child process activity or additional malicious behavior was identified during the available investigation.

### Evidence 1 – TrustedInstaller Process Context

<p align="center">
  <img
    width="769"
    height="508"
    alt="TrustedInstaller process investigation"
    src="https://github.com/user-attachments/assets/5474968e-fee5-4a5d-adb4-e0dfbae6e250"
  />
</p>

<p align="center">
  <em>
    Figure 1 – Investigation of the <code>TrustedInstaller.exe</code> activity showed a process context and executable location consistent with the legitimate Windows Modules Installer service.
  </em>
</p>

### Evidence 2 – TrustedInstaller Process Creation Event

<p align="center">
  <img
    width="1199"
    height="95"
    alt="TrustedInstaller Sysmon process creation event"
    src="https://github.com/user-attachments/assets/c8046768-1d6b-4e34-ba02-429cadc2b34d"
  />
</p>

<p align="center">
  <em>
    Figure 2 – A Sysmon Event ID <code>1</code> Process Create event recorded <code>TrustedInstaller.exe</code> on <code>win-3459</code> with PID <code>3577</code> at <code>08/21/2026 14:55:45.419</code>.
  </em>
</p>

## Indicators & Entities

- **Affected Host:** `win-3459`
- **Parent Process:** `services.exe`
- **Child Process:** `TrustedInstaller.exe`
- **TrustedInstaller PID:** `3577`
- **TrustedInstaller Path:** `C:\Windows\servicing\TrustedInstaller.exe`
- **Event Type:** Sysmon Event ID `1` – Process Create
- **Observed Activity:** Windows service / servicing activity
- **Classification:** False Positive

## Observed Process Chain

The observed process relationship was:

`services.exe`  
→ `TrustedInstaller.exe`  
→ `C:\Windows\servicing\TrustedInstaller.exe`

A Sysmon Process Create event recorded `TrustedInstaller.exe` running on `win-3459` with PID `3577`.

The process relationship and executable path were consistent with legitimate Windows servicing activity.

No suspicious child processes, unusual execution paths, or additional malicious behavior were identified during the available investigation.

## Analysis

The alert was triggered by an uncommon parent-child process relationship involving `services.exe` and `TrustedInstaller.exe`.

Unusual process relationships can be important during SOC investigations because attackers may abuse legitimate Windows processes or system services to execute malicious code.

However, process names and parent-child relationships should not be evaluated in isolation.

`services.exe` is a legitimate Windows component responsible for managing system services, while `TrustedInstaller.exe` is associated with the Windows Modules Installer service.

The investigated `TrustedInstaller.exe` process was associated with the expected Windows servicing path:

`C:\Windows\servicing\TrustedInstaller.exe`

A Sysmon Event ID `1` Process Create event also confirmed the presence of `TrustedInstaller.exe` on host `win-3459` with PID `3577`.

Further review did not identify:

- An unexpected executable path
- A suspicious command line
- Suspicious child process activity
- Additional behavior indicating malware execution
- Other evidence suggesting process abuse or compromise

When the process relationship, executable path, and surrounding activity were correlated, the behavior was more consistent with legitimate Windows servicing activity than malicious execution.

The alert was therefore assessed as normal system behavior that triggered the detection logic.

## Verdict

⚪ **False Positive**

The alert was classified as a False Positive because the investigated process activity was consistent with legitimate Windows service behavior.

`TrustedInstaller.exe` was observed on `win-3459` with PID `3577` and was associated with the expected Windows servicing path:

`C:\Windows\servicing\TrustedInstaller.exe`

No suspicious execution path, command-line behavior, child process activity, or additional malicious indicators were identified during the investigation.

The available evidence therefore supported legitimate Windows system activity rather than malicious process execution.

> [!TIP]
> **Key Takeaway:** An unusual parent-child process relationship should trigger investigation, but it should not automatically be classified as malicious. Process path, command-line context, child processes, and surrounding activity should be reviewed before making a final decision.

## Recommended Actions

Because the activity was classified as legitimate Windows behavior, no containment or remediation action was required for the investigated process.

Recommended analyst actions include:

- Close the alert as a False Positive after documenting the investigation findings.
- Record the legitimate `services.exe` → `TrustedInstaller.exe` process relationship for future reference.
- Continue monitoring for changes in executable path, command-line behavior, or child process activity.
- Reinvestigate similar alerts if `TrustedInstaller.exe` appears outside the expected Windows servicing directory.
- Escalate future activity if the process relationship is accompanied by suspicious commands, unexpected child processes, or other indicators of compromise.
- Consider detection tuning only if the same verified benign pattern generates repeated unnecessary alerts and tuning would not reduce meaningful security visibility.

## Lessons Learned

This investigation reinforced several important SOC analysis principles:

- An unusual parent-child process relationship does not automatically indicate malicious activity.
- Legitimate Windows system processes can generate security alerts because detection logic may identify unusual behavior without confirming malware.
- Parent-child process relationships should be evaluated together with executable paths, command lines, and surrounding process activity.
- The expected path of a Windows system executable is an important validation point during process investigations.
- A legitimate process name alone is not enough to confirm that a process is benign; its path and behavior should also be reviewed.
- Sysmon Process Create events can help confirm when and where a process was observed and provide useful investigation context.
- The absence of suspicious child processes or additional malicious behavior can support a benign classification when combined with other evidence.
- False Positive investigations are an important SOC skill because unnecessary escalation can consume analyst time and reduce attention available for genuine threats.
- Detection tuning should only be considered after a benign pattern has been sufficiently validated.
