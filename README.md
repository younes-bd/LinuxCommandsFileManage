<h1>File permissions in Linux </h1>

<h2>Description</h2>
The research team at my organization needs to update the file permissions for certain files and directories within the projects directory. The permissions do not currently reflect the level of authorization that should be given. Checking and updating these permissions will help keep their system secure. To complete this task, I performed the following tasks:
<br />



<h2>Check file and directory details: </h2>
 
 The following code demonstrates how I used Linux commands to determine the existing permissions set for a specific directory in the file system.
 <br/>
 <br/>
 <img src="https://i.imgur.com/dPlSonb.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 <br/>

The first line of the screenshot displays the command I entered, and the other lines display the output. The code lists all contents of the projects directory. I used the ls command with the -la option to display a detailed listing of the file contents that also returned hidden files. The output of my command indicates that there is one directory named drafts, one hidden file named .project_x.txt, and five other project files. The 10-character string in the first column represents the permissions set on each file or directory.
 

<h2> Describe the permissions string: </h2>
 
 The 10-character string can be deconstructed to determine who is authorized to access the file and their specific permissions. The characters and what they represent are as follows: <br/>
- 1st character: This character is either a d or hyphen (-) and indicates the file type. If it’s a d, it’s a directory. If it’s a hyphen (-), it’s a regular file. <br/>
- 2nd-4th characters: These characters indicate the read (r), write (w), and execute (x) permissions for the user. When one of these characters is a hyphen (-) instead, it indicates that this permission is not granted to the user. <br/>
-	5th-7th characters: These characters indicate the read (r), write (w), and execute (x) permissions for the group. When one of these characters is a hyphen (-) instead, it indicates that this permission is not granted for the group. <br/>
-	8th-10th characters: These characters indicate the read (r), write (w), and execute (x) permissions for other. This owner type consists of all other users on the system apart from the user and the group. When one of these characters is a hyphen (-) instead, that indicates that this permission is not granted for other. <br/>

For example, the file permissions for project_t.txt are -rw-rw-r--. Since the first character is a hyphen (-), this indicates that project_t.txt is a file, not a directory. The second, fifth, and eighth characters are all r, which indicates that user, group, and other all have read permissions. The third and sixth characters are w, which indicates that only the user and group have write permissions. No one has execute permissions for project_t.txt.
 

<h2> Change file permissions: </h2>
 
The organization determined that other shouldn't have write access to any of their files. To comply with this, I referred to the file permissions that I previously returned. I determined project_k.txt must have the write access removed for other. <br/>
The following code demonstrates how I used Linux commands to do this:
 <br/>
 <br/>
<img src="https://i.imgur.com/A0Qu5hb.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 <br/>
The first two lines of the screenshot display the commands I entered, and the other lines display the output of the second command. The chmod command changes the permissions on files and directories. The first argument indicates what permissions should be changed, and the second argument specifies the file or directory. In this example, I removed write permissions from other for the project_k.txt file. After this, I used ls -la to review the updates I made.


<h2> Change file permissions on a hidden file: </h2>
 The research team at my organization recently archived project_x.txt. They do not want anyone to have write access to this project, but the user and group should have read access. <br/>
The following code demonstrates how I used Linux commands to change the permissions:
<br/>
<br/>
 <img src="https://i.imgur.com/EPXXLNY.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br/>
The first two lines of the screenshot display the commands I entered, and the other lines display the output of the second command. I know .project_x.txt is a hidden file because it starts with a period (.). In this example, I removed write permissions from the user and group, and added read permissions to the group. I removed write permissions from the user with u-w. Then, I removed write permissions from the group with g-w, and added read permissions to the group with g+r. 
 

<h2> Change directory permissions: </h2>
 
My organization only wants the researcher2 user to have access to the drafts directory and its contents. This means that no one other than researcher2 should have execute permissions.<br/>
The following code demonstrates how I used Linux commands to change the permissions:
<br/>
<br/>
 <img src="https://i.imgur.com/xdJrvGr.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 

<h2> Summary: </h2>
 
I changed multiple permissions to match the level of authorization my organization wanted for files and directories in the projects directory. The first step in this was using ls -la to check the permissions for the directory. This informed my decisions in the following steps. I then used the chmod command multiple times to change the permissions on files and directories.
 <br/>
 <br/>


 Vulnerability Scanning with Nessus

Description:
As a cybersecurity analyst, you were tasked with performing a vulnerability assessment on your organization's internal network using the Nessus vulnerability scanner.

Linux Commands:

bash
Copy code
# Start Nessus in a Docker container (if Docker is used)
docker run -d --name nessus -p 8834:8834 -e "NESSUS_LICENSE=your-activation-code" nessus/nessus

# Open a web browser and navigate to Nessus web interface
# Login to the Nessus web interface, configure the scan, and initiate the vulnerability scan

Summary:
This project involved setting up and running a Nessus vulnerability scan to identify potential security issues within our organization's network. The Nessus scanner was deployed within a Docker container for ease of use. By conducting this scan, we gained insights into vulnerabilities and areas for security improvement.


Security Patch Management

Description:
Your organization needs to apply security patches to a Linux server to address known vulnerabilities and improve system security.

Linux Commands:

bash
Copy code
# Update package repositories
sudo apt update

# Upgrade installed packages, applying available security patches
sudo apt upgrade

# Review available security patches
sudo apt list --upgradable

# Install specific security updates
sudo apt install package-name

# Apply kernel security updates
sudo reboot

Summary:
In this project, we focused on enhancing system security by applying security patches to a Linux server. We began by updating the package repositories and upgrading installed packages to ensure all security patches were in place. This proactive approach helps safeguard our systems against known vulnerabilities.

Security Hardening with IPTables

Description:
You're tasked with configuring IPTables to restrict network traffic on a Linux server. Security hardening includes allowing only necessary services and blocking others.

Linux Commands:

bash
Copy code
# Allow SSH (replace xx.xx.xx.xx with your IP)
sudo iptables -A INPUT -p tcp --dport 22 -s xx.xx.xx.xx -j ACCEPT

# Allow HTTP and HTTPS traffic
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Drop all other incoming traffic
sudo iptables -A INPUT -j DROP

# Save the rules
sudo iptables-save > /etc/iptables.rules

# Enable IPTables on boot
sudo systemctl enable netfilter-persistent
Summary:
This project focused on enhancing network security through the configuration of IPTables on a Linux server. By explicitly allowing only necessary services and blocking all other incoming traffic, we reduce the attack surface and fortify our system against potential threats.

System Log Analysis

Description:
You've been monitoring system logs to detect unusual activities and potential security incidents. This is a critical task for a cybersecurity analyst.

Linux Commands:

bash
Copy code
# Check the system logs (e.g., syslog)
cat /var/log/syslog

# Search for specific keywords (e.g., 'suspicious activity')
grep 'suspicious activity' /var/log/syslog

# Analyze authentication logs
cat /var/log/auth.log

# Monitor real-time logs
tail -f /var/log/syslog
Summary:
In this project, we delved into system log analysis, a vital aspect of cybersecurity monitoring. We examined various system logs, searched for specific keywords, and monitored real-time logs to identify potential security incidents and unusual activities. This ongoing monitoring is essential for maintaining a secure environment.

Intrusion Detection with Snort

Description:
You've configured Snort, an intrusion detection system, to monitor network traffic for signs of suspicious or malicious activity.

Linux Commands:

bash
Copy code
# Start Snort in IDS mode with a specific configuration file
sudo snort -q -A console -q -c /etc/snort/snort.conf -i eth0

# Analyze Snort logs for alerts
cat /var/log/snort/alert

# Review Snort rules and customize for your network
sudo nano /etc/snort/rules/local.rules

Summary:
This project revolved around setting up and configuring Snort, an intrusion detection system, to monitor network traffic for signs of suspicious or malicious activity. By analyzing Snort logs and customizing rules, we enhance our network's security posture and strengthen our ability to detect and respond to potential intrusions.

<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>
