# Narrative
On Monday morning, a Fortinet firewall within G1039's environment has begun experiencing intermittent connectivity issues that are disrupting Microsoft AD authentication processes across multiple Red Hat-based systems in the network. Simultaneously, unusual login attempts to Google Workspace have been detected on several devices with privileged access rights. As these anomalies grow more frequent and persistent over time, there is concern amongst security personnel about a potential sophisticated threat actor employing advanced tactics targeted at our technology stacks—Fortinet for network defense, Microsoft AD for identity services within the Red Hat environment, and Google Workspace as an additional access point.

# Inject 1: "Sneaky Shadow" Campaign with Command & Concealment Techniques (T1560.001)
**Objective**: Identify a stealth campaign that leverages command and control servers to exfiltrate sensitive information from Red Hat-based systems via Google Workspace emails while maintaining covert communication using mimicked authentication logs.
**Log Evidence**:
```json
{
  "timestamp": "2025-04-22T09:00:00Z",
  "event": "Unusual login from privileged user 'admin' to Google Workspace via Fortinet firewall.",
  "source": "user1.privileged@domain.com",
  "details": "Login attempt timestamped at a regular maintenance window, using MFA-bypass exploit in Microsoft AD and redirecting traffic through an obfuscated IP address."
}
```
# Inject 2: Fortinet Syslog Tamper (T1053.005)
**Objective**: Detect tampered syslog entries designed to mislead the incident response team by falsely indicating normal activities within our network segments protected by Fortinet devices, while also creating confusion about an internal threat actor's involvement with Google Workspace credentials (T1204.002).
**Log Evidence**:
```json
{
  "timestamp": "2025-0404T09:00:00Z",
  "event": "'admin' user attempts to access sensitive files through mimicked Google Workspace email.",
  "source": "user1.privileged@domain.com",
  "details": "Syslog entry timestamped during non-existent business hours with modified IPs pointing back to Fortinet devices."
}
```
# Inject 3: Persistence and Escalation via Privilege Manipulation (T1087.001)
**Objective**: Uncover tactics used by an attacker that exploits privilege escalation vulnerabilities in the Microsoft AD environment to gain higher privileges on Red Hat systems, potentially using Google Workspace for communication and command dissemination purposes.
**Log Evidence**:
```json
{
  "timestamp": "2025-04-22T09:00:00Z",
  "event": "'admin' user performs privilege escalation to execute commands on Red Hat systems.",
  "source": "user1.privileged@domain.com",
  "details": "User exploits a known vulnerability in Microsoft AD, with subsequent activities timestamped shortly after gaining higher privileges."
}
```
# Facilitation Tips
- Ensure that all team members are familiar with the baseline of normal activity patterns and know how to differentiate between benign anomalies and malicious events.
- Provide continuous updates on inject timings, expected outcomes, or any changes in tactics without revealing too much detail upfront; this keeps attackers guessing while also preventing unnecessary alarm bells from going off within the network due to predictable patterns.
- Use a mix of automated tools and manual inspection for log analysis to uncover hidden communication channels that may be using Google Workspace, emphasizing the need to look beyond surface indicators like user credentials or authentication logs (T1087.002).
- Remind facilitators to keep an eye out on Fortinet devices' syslog tampering and ensure they understand how such entries can misdirect investigations by altering timestamps and IP addresses, which are crucial for maintaining a realistic simulation environment (T1053.002).
- Discuss the importance of understanding privilege management within Microsoft AD to effectively respond when escalation attempts occur; this includes recognizing common vulnerabilities that attackers could exploit during exergy or Red Hat system interactions, especially regarding Google Workspace's role in command and control communication (T1087.002).
- Use the scenario’s intermittent connectivity issues as a red herring to distract from critical activities occurring within Microsoft AD authentication processes while still allowing room for recognizing legitimate traffic spikes that might correlate with inject timings, reinforcing adaptability in investigative skills.