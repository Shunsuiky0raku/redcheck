In today’s cybersecurity landscape, Red Hat Enterprise Linux (RHEL) serves as a key operating system across many enterprise and government environments due to its reliability, stability, and strong vendor support. Despite its strengths, RHEL servers remain susceptible to misconfigurations, weak policies, and neglected system services. These vulnerabilities often go unnoticed, especially when administrators lack tools that efficiently and consistently evaluate the system’s security posture.
While the Windows ecosystem benefits from mature tools like PingCastle for Active Directory health auditing, there is a clear gap in the Linux ecosystem for a similar lightweight, CLI-based tool. Existing Linux security scanners such as OpenSCAP or Lynis are either compliance-heavy or generalized, making them difficult to use in fast-paced operational or red team scenarios. Furthermore, many system administrators still rely on manual checklists, which are time-consuming, error-prone, and rarely aligned with industry-recognized benchmarks such as the CIS (Center for Internet Security) guidelines.
To address this gap, this project proposes SysHealth, a dual-use command-line tool designed specifically for auditing the security posture of RHEL-based servers. The tool will be useful for both system administrators (defensive security) and penetration testers (offensive security/reconnaissance). It will scan the system against a subset of CIS Benchmark controls and common hardening best practices, calculate a security score, and generate actionable output in both terminal and exportable formats.

Aim
To develop a speedy, benchmark-based command-line tool for auditing the security profile of Red Hat Enterprise Linux servers, providing structured output for consumption by students penetration testers and system administrators alike.



Objectives
The project goals are as follows:
1. To deploy a modular, CIS-benchmark-conformant scanning engine that examines the most critical security controls surrounding authentication, access control, and network services on RHEL-based systems.
2. To create a weighted scoring system that quantifies a server's security stance with a global health score and category-by-category breakdowns to enable quick risk assessments.
3. To provide a red-team reconnaissance mode that highlights privilege escalation paths based on the poorly configured settings.
4. To enable multi-format reporting (terminal, JSON) with actionable remediation.


Targeted Users

This project is designed for the following user groups:

• System Administrators: who need to regularly audit and harden their Linux environments based on industry benchmarks.

• Penetration Testers and Red Teams: who require reconnaissance capabilities on compromised Linux systems without installing large scanners.

• Security Auditors and Compliance Teams: who need a way to verify CIS alignment and export audit logs or scores.
•Students, CTF Players, and Self-Learning Ethical Hacking Students 
