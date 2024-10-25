# ~ Threat-Detection-Incident-Response-Using-ELK

This project focuses on automating critical SOC components, which include setting up the ELK stack for log monitoring, detecting brute-force attacks on SSH and RDP servers, simulating attacks with a Mythic C2 server, and integrating a ticketing system for alert investigation and response.

# ~ Step 1: Building a Centralized Logging System
# Set up the ELK stack and configured Sysmon for log ingestion.

# * Created Logical Diagram using draw.io ![1  Block Diagram](https://github.com/user-attachments/assets/c234a80b-6c80-4301-91ab-d6bb0d9d488e)

# * Installed Virtual Machines: 4 Ubuntu VMs, 1 Kali Linux VM, 1 Windows 10 VM, and 1 Windows Server 2022 VM.

# ![2  Virtual Machines](https://github.com/user-attachments/assets/8c090246-0600-473a-8efb-009273510a01)

# Installed the Elastic Stack and Kibana on Ubuntu 22.04, designated as 'Ubuntu ELK.

# * Elastic ![Download Elastic ](https://github.com/user-attachments/assets/1d3c5456-fa88-4ff2-ab64-a8628aa0809e)

# * Kibana ![Download Kibana](https://github.com/user-attachments/assets/dc61626a-b9fa-4fc8-b51f-6a328c035aaf)

# * Accessed the Elastic dashboard at http://IP-Address:5601 in a web browser.

# ![Elastic Web GUI](https://github.com/user-attachments/assets/28592ee4-8be5-495d-84cf-ffb524db6a01)

# Installed and configured Sysmon and the Elastic Agent on the Windows 10 host.

# * Sysmon ![6  Sysmon](https://github.com/user-attachments/assets/faee5fb7-7447-4ef4-99ec-dbfa628746d4)

# * Elastic Agent ![7  Elastic Agent](https://github.com/user-attachments/assets/53fd1e39-5bae-4e43-aa09-1e95429eb85f)

# Installed and configured the Fleet Server on the host named 'Ubuntu Fleet.

# ![8  Fleet Server](https://github.com/user-attachments/assets/bd45eb7f-cff0-44af-8dda-3801afe2d76e)

# Configured Windows Sysmon and Windows Defender within the Elastic GUI in the Agent Policies section.

# ![9  Sysmon   Defender](https://github.com/user-attachments/assets/991ce68b-d35c-4885-8191-3c6f7b5df1e4)

# Ingested logs from Sysmon and Windows Defender.

# ![10  Ingested Logs](https://github.com/user-attachments/assets/a563eb8f-0c7c-43c8-b8b3-9781d982a299)

# ~ Step 2: Implementing Secure Access 

# Set up SSH and RDP servers, detected brute-force attacks, and monitored activities using dashboards.

# * Enabled RDP on the host named 'Win 22 (Karthik-Agent)' and SSH on the host named 'Ubuntu (Karthik-Agent).' ![11  RDP Enabled](https://github.com/user-attachments/assets/822d81dd-4d82-4b5c-a5eb-63fa2c8a23d5)

# * Executed a brute-force attack on 'Win 22 (Karthik-Agent)' using the Crowbar tool in Kali Linux to generate logs for analysis in the Elastic dashboard.

# ![12  RDP Brute Force](https://github.com/user-attachments/assets/a8fef5f3-e888-4b00-a753-41f4c546c24d)

# Created brute-force alerts for both RDP on 'Win 22 (Karthik-Agent)' and SSH on 'Ubuntu (Karthik-Agent)' in the Elastic UI.

# * RDP Brute Force Alerts ![13  RDP](https://github.com/user-attachments/assets/f8584033-f9be-4f3b-b0fe-eaacd0b1ad64)

# * SSH  Brute Force Alerts ![14  SSH](https://github.com/user-attachments/assets/4fc92f8c-096d-46e7-bb0a-bf0eb5a51874)

# Developed a dashboard in the Elastic UI to monitor successful and failed authentication attempts for SSH and RDP.

# * SSH Successful & Failed Authentications ![15  SSH Dashboard](https://github.com/user-attachments/assets/1d0a0577-10eb-4d41-baee-6df682a75072)

# * RDP Successful & Failed Authentications ![16  RDP Dashboard](https://github.com/user-attachments/assets/2bbc7dc3-f8da-4cf0-bab8-7d0bf5aff69d)

# ~ Step 3: Building and Testing Command and Control (C2) Infrastructure

# Set up the Mythic C2 server and simulated attacks on public servers.

# * Installed and configured the Mythic Command and Control (C2) server on the host named 'Ubuntu (Mythic).'

#  ![17  Mythic](https://github.com/user-attachments/assets/1b0d57a5-e0fd-4860-99bb-167cab16352e)

# Created a logical diagram for the Mythic C2 attack, illustrating the phases of the process.

# * Phase-1 Initial Access ![18  Phase-1](https://github.com/user-attachments/assets/a790166e-d896-463b-ada3-4a3c143fa602)

# * RDP Brute Force ![12  RDP Brute Force](https://github.com/user-attachments/assets/d9eea15f-f7d9-4948-8c90-82f6360adfa0)

# * RDP Authentication Successful from Attacker machine kali ![18 1 Authentication Success](https://github.com/user-attachments/assets/fcb05111-6c51-4366-adb4-c3ea74cab4de)

# * Phase-2 Discovery ![19  Phase-2](https://github.com/user-attachments/assets/ad96189d-4d33-41be-bb35-35f15ca1e1b5)

# * Discovered via RDP ![19 2 Discovery Via RDP](https://github.com/user-attachments/assets/314a5e08-4595-4d21-a223-4f95db4aa1f1)

# * Phase-3 Defender Evasion ![20  Phase-3](https://github.com/user-attachments/assets/6c5918e8-c2f2-438d-b82a-3ed852bdd180)

# * Completed Defender Evasion ![20 1 Defender Evasion](https://github.com/user-attachments/assets/0e7c069f-b96c-4c02-9cd8-114994580933)

# * Phase-4 Execution ![21  Phase-4](https://github.com/user-attachments/assets/f515c3dc-e571-4360-9988-7c575b6d576f)

# * Completed Payload Execution ![21 1 Execution ](https://github.com/user-attachments/assets/3d6c387b-03fc-45d5-bc0c-9cbe48cce221)

# * Phase-5 Command & Control ![22  Phase-5](https://github.com/user-attachments/assets/9cfca8fb-5b76-47ec-b98c-a35a647675d4)

# * Completed Command & Control ![22 1 C2](https://github.com/user-attachments/assets/a36356e0-3e46-40ab-983b-121fe626fb5f)

# * Phase-6 Exfiltration ![23  Phase-6](https://github.com/user-attachments/assets/40bcece7-eeae-4a33-bac1-645696b86470)

# * Completed Exfiltration ![23 1 Exfiltration](https://github.com/user-attachments/assets/6de2e31b-70d3-4adc-8a07-75b3c4a1580f)

# * Configured alerts for the Mythic C2 server. ![24  Mythic Alerts](https://github.com/user-attachments/assets/f6fac524-2fbb-4d09-9e7d-47069b5ee92e)

# * Developed a dashboard for the Mythic C2 server. ![25  Dashboard Attack](https://github.com/user-attachments/assets/40b5295d-56b5-470a-bf26-db0e08ff5799)

# * Established rules for detecting RDP, SSH, and Mythic C2 attacks. ![26  Rules](https://github.com/user-attachments/assets/b04c8f11-455d-4c46-b0ce-19ca5458ba18)

# * Generated alerts for RDP, SSH, and Mythic C2 attacks. ![27  Alerts](https://github.com/user-attachments/assets/021084cc-0dd3-4b94-baa0-59bcedc82fc5)

# ![27 1 Alerts](https://github.com/user-attachments/assets/4a271cc6-8983-4024-b81b-5d243e2156ae)

# ~ Step 4: Implementing and Integrating Ticketing Systems for Efficient Alert Management and Investigation

# Implemented and integrated ticketing systems to enhance alert management and streamline investigation processes. 

# * Accessed the osTicket UI in a web browser at http://IP-Address/osticket/upload/scp ![28  OSTICKET](https://github.com/user-attachments/assets/8b648536-eb90-453b-8980-c3c2199f267d)

# * osTicket Admin Panel ![OSticket](https://github.com/user-attachments/assets/1a8ad9e0-2fef-4c12-bd95-f26921a3f3aa)

# * Configured an osTicket webhook under the rule settings in the Elastic UI. ![29  Webhook](https://github.com/user-attachments/assets/2b5a0d55-956f-4a66-bd6e-71d270c0aefa)

# * Automatically forwards triggered alerts to osTicket. ![OsTicket alert](https://github.com/user-attachments/assets/6eadb12f-6c2b-4cc0-8de1-3353048a36db)

# * Integrated Elastic Defender within the Elastic UI. ![30  Integrated Elastic Defender](https://github.com/user-attachments/assets/02359325-f245-4812-ad44-adbca23fcf79)

# ![32  Elastic Endpoint ](https://github.com/user-attachments/assets/5cc3cf37-df3b-421b-8ae6-e45b747ff249)

# * When attempting to run 'SVCHOST.karthikrocks.exe,' Elastic Defender blocks the execution." ![31  Malware alert](https://github.com/user-attachments/assets/ce0c9f6f-390b-4458-b825-801c373e0128)

# * Elastic Defender isolates the endpoint upon detecting malware. ![Screenshot 2024-10-21 105017](https://github.com/user-attachments/assets/47b2119f-88ff-4e96-b846-8d74b2855e88)

# ![34  Isolated](https://github.com/user-attachments/assets/4d658dcd-25fa-4124-a439-df745fc94ab5)

# When an endpoint is isolated, analysts typically follow these steps:

# Assessment of Isolation:
* Confirm that the endpoint has been successfully isolated to prevent further threats or unauthorized access.

# Investigation:
* Examine logs and alerts related to the isolated endpoint to determine the nature and extent of the compromise.
* analyze the malware or suspicious activity to understand its impact and identify the attack vector.

# Containment:
* Ensure that any affected systems are contained and that there is no further spread of the threat within the network.

# Remediation:
* Remove the malware or any malicious files from the endpoint.
* Apply patches or updates to address any vulnerabilities exploited during the attack.

# Recovery:
* Restore the endpoint to normal operation, ensuring it is clean and secure.
* Reconnect the endpoint to the network after confirming it is safe.

# Documentation:
* Document all findings, actions taken, and the timeline of the incident for future reference and compliance.

# Post-Incident Analysis:
* Conduct a review of the incident to identify lessons learned and improve security measures.
* Update incident response plans and security protocols based on insights gained from the investigation.

# Communication:
* Inform relevant stakeholders, including management and possibly affected users, about the incident and any necessary actions they need to take.

# This process ensures a thorough and systematic response to isolated endpoints, mitigating risks and enhancing overall security posture.
