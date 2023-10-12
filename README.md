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
```
# Start Nessus in a Docker container (if Docker is used)
docker run -d --name nessus -p 8834:8834 -e "NESSUS_LICENSE=your-activation-code" nessus/nessus
# Open a web browser and navigate to Nessus web interface
# Login to the Nessus web interface, configure the scan, and initiate the vulnerability scan
```
Summary:
This project involved setting up and running a Nessus vulnerability scan to identify potential security issues within our organization's network. The Nessus scanner was deployed within a Docker container for ease of use. By conducting this scan, we gained insights into vulnerabilities and areas for security improvement.


Security Patch Management

Description:
Your organization needs to apply security patches to a Linux server to address known vulnerabilities and improve system security.

Linux Commands:
```
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
```
Summary:
In this project, we focused on enhancing system security by applying security patches to a Linux server. We began by updating the package repositories and upgrading installed packages to ensure all security patches were in place. This proactive approach helps safeguard our systems against known vulnerabilities.

Security Hardening with IPTables

Description:
You're tasked with configuring IPTables to restrict network traffic on a Linux server. Security hardening includes allowing only necessary services and blocking others.

Linux Commands:
```
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
```

Summary:
This project focused on enhancing network security through the configuration of IPTables on a Linux server. By explicitly allowing only necessary services and blocking all other incoming traffic, we reduce the attack surface and fortify our system against potential threats.

System Log Analysis

Description:
You've been monitoring system logs to detect unusual activities and potential security incidents. This is a critical task for a cybersecurity analyst.

Linux Commands:
```
# Check the system logs (e.g., syslog)
cat /var/log/syslog

# Search for specific keywords (e.g., 'suspicious activity')
grep 'suspicious activity' /var/log/syslog

# Analyze authentication logs
cat /var/log/auth.log

# Monitor real-time logs
tail -f /var/log/syslog
```

Summary:
In this project, we delved into system log analysis, a vital aspect of cybersecurity monitoring. We examined various system logs, searched for specific keywords, and monitored real-time logs to identify potential security incidents and unusual activities. This ongoing monitoring is essential for maintaining a secure environment.

Intrusion Detection with Snort

Description:
You've configured Snort, an intrusion detection system, to monitor network traffic for signs of suspicious or malicious activity.

Linux Commands:

```
# Start Snort in IDS mode with a specific configuration file
sudo snort -q -A console -q -c /etc/snort/snort.conf -i eth0

# Analyze Snort logs for alerts
cat /var/log/snort/alert

# Review Snort rules and customize for your network
sudo nano /etc/snort/rules/local.rules
```

Summary:
This project revolved around setting up and configuring Snort, an intrusion detection system, to monitor network traffic for signs of suspicious or malicious activity. By analyzing Snort logs and customizing rules, we enhance our network's security posture and strengthen our ability to detect and respond to potential intrusions.

Network Scanning with Nmap

Description:
Your organization requested a network scan to identify open ports and services on a target host. You performed this scan using the Nmap network scanning tool.

Linux Commands:

```
# Scan a target host for open ports
nmap target-host

# Scan a range of IP addresses
nmap 192.168.1.1-50

# Scan a specific port range
nmap -p 80-100 target-host

# Save the scan results to a file
nmap -oN scan-results.txt target-host
```
Summary:
This project involved conducting a network scan on a target host using Nmap. The scan revealed open ports and services on the target, providing valuable insights into potential vulnerabilities. The results were saved for further analysis and to assist in securing the network.

Server Hardening with SSH Configuration

Description:
Your task was to enhance the security of a Linux server by configuring SSH (Secure Shell) to use key-based authentication, disabling password-based logins, and implementing other security measures.

Linux Commands:

```
# Generate an SSH key pair (if not already generated)
ssh-keygen -t rsa

# Copy the public key to the remote server for key-based authentication
ssh-copy-id user@remote-host

# Edit SSH server configuration
sudo nano /etc/ssh/sshd_config

# Disable password-based logins
PasswordAuthentication no

# Restart the SSH service to apply changes
sudo systemctl restart ssh
```

Summary:
In this project, the focus was on improving server security by configuring SSH for key-based authentication and disabling password-based logins. These measures bolstered the server's security posture, making it less vulnerable to unauthorized access.

Incident Response Simulation

Description:
Your organization conducted an incident response simulation to test the effectiveness of the response plan in the event of a security incident.

Linux Commands:

```
# Simulate a security incident by creating a test file
touch /var/test-incident-file.txt

# Generate log entries related to the incident
echo "Unauthorized access detected" >> /var/log/security.log

# Execute the incident response plan
Follow predefined procedures for incident containment, investigation, and recovery
```

Summary:
In this incident response simulation, you practiced the initial steps taken in response to a security incident. By creating a test incident file and generating corresponding log entries, you assessed the effectiveness of the incident response plan and made improvements as needed.

Forensic Analysis of Suspicious File

Description:
You were tasked with analyzing a suspicious file to determine its origin and whether it poses a security threat.

Linux Commands:

```
# Create a copy of the suspicious file for analysis
cp suspicious-file /var/forensics/

# Analyze the file using various forensic tools
strings /var/forensics/suspicious-file
hexdump -C /var/forensics/suspicious-file
file /var/forensics/suspicious-file

# Review system logs for any related activities
cat /var/log/auth.log
```
Summary:
This project involved conducting a forensic analysis of a suspicious file to identify potential security risks. By using Linux commands and forensic tools, you gained insights into the file's content and origin, aiding in the organization's security decision-making.

Endpoint Security Management with SELinux

Description:
Your task was to implement SELinux (Security-Enhanced Linux) policies to enhance endpoint security on Linux systems.

Linux Commands:

```
# Check the current SELinux status
sestatus

# Install SELinux utilities (if not already installed)
sudo yum install policycoreutils

# Modify SELinux policy to control access for specific processes
sudo semanage permissive -a httpd_t

# Apply SELinux policies and relabel the file system
sudo touch /.autorelabel
sudo reboot
```

Summary:
In this project, you focused on improving endpoint security by implementing SELinux policies. By controlling access for specific processes, you strengthened security controls and enhanced the overall security of Linux systems.

Linux Kernel Patching for Security

Description:
Your organization required a critical security patch to be applied to the Linux kernel to address a known vulnerability.

Linux Commands:

bash
Copy code
# Check the current kernel version
uname -r

# Download the latest kernel patch from the official source
wget https://www.kernel.org/pub/linux/kernel/v5.x/linux-5.x.x.tar.xz

# Extract the kernel source code
tar -xvf linux-5.x.x.tar.xz

# Apply the security patch
cd linux-5.x.x
patch -p1 < security-patch.diff

# Recompile and install the patched kernel
make && make modules_install && make install

# Reboot the system to load the new kernel
reboot
Summary:
In this project, you demonstrated your ability to apply a critical security patch to the Linux kernel, thus addressing a known vulnerability and enhancing the system's security.

Intrusion Detection System (IDS) Configuration

Description:
Your task was to set up an IDS (Intrusion Detection System) on a Linux server to monitor network traffic for potential security threats.

Linux Commands:

bash
Copy code
# Install the Snort IDS system
sudo apt-get install snort

# Configure Snort rules and policies
sudo nano /etc/snort/snort.conf
sudo nano /etc/snort/rules/local.rules

# Start the Snort IDS service
sudo systemctl start snort
sudo systemctl enable snort
Summary:
In this project, you successfully configured an IDS on a Linux server, allowing it to monitor network traffic for suspicious activity and potential security threats. This is a crucial step in enhancing network security.

Log Analysis for Security Monitoring

Description:
Your organization needed to improve its security monitoring by analyzing log files to detect and respond to security incidents.

Linux Commands:

bash
Copy code
# Collect and analyze system logs
grep "Unauthorized access" /var/log/auth.log
grep "malware detected" /var/log/syslog

# Create custom log analysis scripts
nano analyze-logs.sh

# Automate log analysis with cron jobs
crontab -e
Summary:
This project focused on setting up log analysis processes on a Linux system to monitor for unauthorized access and malware detection. By creating custom log analysis scripts and automating the analysis, you improved security monitoring capabilities.

Hardening SSH Configuration

Description:
You were tasked with enhancing the security of SSH by modifying its configuration to adhere to best practices.

Linux Commands:

bash
Copy code
# Edit SSH server configuration
sudo nano /etc/ssh/sshd_config

# Disable root login
PermitRootLogin no

# Set idle timeout for SSH sessions
ClientAliveInterval 300
ClientAliveCountMax 0

# Implement rate-limiting for login attempts
MaxAuthTries 3

# Restart the SSH service to apply changes
sudo systemctl restart ssh
Summary:
In this project, you improved the security of SSH by modifying its configuration to disable root logins, set an idle timeout, and implement rate-limiting for login attempts. These measures enhance the security of remote access to the system.

Security Compliance Auditing with Lynis

Description:
Your organization needed to conduct a security compliance audit on Linux servers to identify vulnerabilities and ensure adherence to security best practices.

Linux Commands:

bash
Copy code
# Install Lynis, a security auditing tool
wget https://cisofy.com/files/lynis-3.x.x.tar.gz
tar -xvf lynis-3.x.x.tar.gz

# Run a security audit with Lynis
cd lynis
sudo ./lynis audit system

# Review the audit report for findings and recommendations
cat /var/log/lynis-report.dat
Summary:
This project involved using Lynis, a security auditing tool, to conduct a comprehensive audit of Linux systems. The audit report provided valuable insights into vulnerabilities and recommendations for improving security and compliance.

Disk Encryption Implementation

Description:
Your organization required sensitive data on Linux servers to be encrypted to protect it in case of unauthorized access.

Linux Commands:

bash
Copy code
# Install encryption tools (e.g., LUKS)
sudo apt-get install cryptsetup

# Create an encrypted volume
sudo cryptsetup luksFormat /dev/sdX

# Open the encrypted volume
sudo cryptsetup open /dev/sdX encrypted-volume

# Format the encrypted volume with a filesystem (e.g., ext4)
sudo mkfs.ext4 /dev/mapper/encrypted-volume

# Mount the encrypted volume
sudo mount /dev/mapper/encrypted-volume /mnt/encrypted-data
Summary:
This project involved implementing disk encryption on Linux servers to protect sensitive data. By creating an encrypted volume, formatting it with a filesystem, and mounting it, you ensured the security of sensitive information.

Implementing Two-Factor Authentication (2FA) for SSH

Description:
Your organization needed to enhance the security of SSH logins by implementing two-factor authentication for user accounts.

Linux Commands:

bash
Copy code
# Install the necessary packages
sudo apt-get install libpam-google-authenticator

# Configure 2FA for a specific user
google-authenticator

# Edit the SSH PAM configuration
sudo nano /etc/pam.d/sshd

# Add the following line to enable 2FA for SSH
auth required pam_google_authenticator.so

# Restart the SSH service
sudo systemctl restart ssh
Summary:
In this project, you improved SSH security by implementing two-factor authentication (2FA) for user accounts. 2FA adds an extra layer of security to the login process.

Setting Up a Linux Bastion Host

Description:
Your organization needed to establish a secure bastion host, also known as a jump host, to control and audit remote access to internal servers.

Linux Commands:

bash
Copy code
# Configure the bastion host server
sudo apt-get install openssh-server

# Create SSH keys for administrators
ssh-keygen -t rsa

# Install the public keys on the bastion host
cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys

# Configure SSH to allow gateway functionality
sudo nano /etc/ssh/sshd_config
Summary:
In this project, you set up a Linux bastion host, a critical component of a secure remote access solution. The bastion host controls and logs access to internal servers.

Linux Disk Space Monitoring

Description:
Your organization required monitoring of disk space on multiple Linux servers to prevent out-of-space issues.

Linux Commands:

bash
Copy code
# Check disk space usage
df -h

# Set up automated disk space alerts
nano disk-space-monitor.sh

# Schedule the script with cron
crontab -e
Summary:
This project focused on implementing disk space monitoring to prevent critical server out-of-space issues. You created a script and scheduled it with cron to provide automated alerts.

Firewall Rule Configuration with iptables

Description:
Your organization needed to configure firewall rules on a Linux server to control incoming and outgoing network traffic.

Linux Commands:

bash
Copy code
# Install iptables
sudo apt-get install iptables

# Define the rules for the firewall
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -j DROP

# Save the firewall rules
sudo apt-get install iptables-persistent
Summary:
In this project, you demonstrated the capability to configure firewall rules using iptables to control incoming and outgoing network traffic on a Linux server.

System Log Rotation and Management

Description:
Your organization needed to set up log rotation and management to ensure that log files do not consume excessive disk space.

Linux Commands:

bash
Copy code
# Configure log rotation
sudo nano /etc/logrotate.conf

# Define log rotation settings for specific log files
sudo nano /etc/logrotate.d/app-logs

# Test log rotation settings
logrotate -d /etc/logrotate.conf
Summary:
This project involved setting up log rotation and management to maintain an organized log history while preventing log files from occupying too much disk space.

Linux User Account Auditing

Description:
Your organization required auditing of user accounts on Linux servers to track and log changes and access.

Linux Commands:

bash
Copy code
# Enable user auditing
sudo nano /etc/audit/auditd.conf
sudo service auditd restart

# Monitor user account changes
auditctl -a always,exit -F arch=b64 -S usermod -k usermod_changes
auditctl -a always,exit -F arch=b64 -S passwd -k passwd_changes

# Review audit logs
ausearch -k usermod_changes

Summary:
In this project, you demonstrated the ability to enable user account auditing on Linux servers, enhancing security by tracking and logging changes and access.

Implementing File Integrity Monitoring (FIM)

Description:
Your organization needed to enhance security by implementing File Integrity Monitoring to detect unauthorized changes to critical system files.

Linux Commands:

bash
Copy code
# Install a FIM tool like Tripwire
sudo apt-get install tripwire

# Initialize and configure Tripwire
sudo tripwire --init
sudo tripwire --update-policy

# Check for changes in the file system
sudo tripwire --check
Summary:
In this project, you improved security by implementing File Integrity Monitoring (FIM) with Tripwire. FIM helps detect and alert on unauthorized changes to system files.

Implementing Log Management with ELK Stack

Description:
Your organization required central log management and analysis to monitor and respond to security events effectively.

Linux Commands:

bash
Copy code
# Install and configure the ELK Stack (Elasticsearch, Logstash, Kibana)
sudo apt-get install elasticsearch logstash kibana

# Set up Logstash to collect and filter logs
# Configure Kibana for log visualization

# Forward logs from Linux servers to the ELK Stack
Summary:
This project involved setting up a powerful log management solution using the ELK Stack to aggregate, analyze, and visualize log data, enhancing the organization's security posture.

Hardening SSH Security

Description:
Your organization wanted to harden the security of the SSH service on Linux servers to prevent unauthorized access.

Linux Commands:

bash
Copy code
# Modify SSH configuration
sudo nano /etc/ssh/sshd_config

# Implement security measures like disabling root login, using key authentication, and limiting login attempts
Summary:
In this project, you focused on hardening SSH security to protect Linux servers from unauthorized access and attacks.

Implementing Network Intrusion Detection with Snort

Description:
Your organization needed a network intrusion detection system to monitor network traffic and detect suspicious or malicious activity.

Linux Commands:

bash
Copy code
# Install Snort
sudo apt-get install snort

# Configure Snort rules and network interfaces
sudo nano /etc/snort/snort.conf

# Start Snort in Network Intrusion Detection mode
sudo snort -q -A console -q -q -c /etc/snort/snort.conf
Summary:
In this project, you implemented network intrusion detection using Snort, enhancing the organization's ability to detect and respond to network-based threats.

Implementing Full Disk Encryption with LUKS

Description:
Your organization needed to secure sensitive data on Linux laptops by implementing full disk encryption.

Linux Commands:

bash
Copy code
# Install LUKS (Linux Unified Key Setup)
sudo apt-get install cryptsetup

# Initialize LUKS encryption
sudo cryptsetup --verbose --verify-passphrase luksFormat /dev/sdX

# Create an encrypted partition and mount it
sudo cryptsetup luksOpen /dev/sdX my_encrypted_partition
Summary:
In this project, you implemented full disk encryption using LUKS to protect sensitive data on Linux laptops.

These projects demonstrate your expertise in Linux-based security practices, further enriching your portfolio as a cybersecurity analyst.

<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>
