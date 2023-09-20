<h1>File permissions in Linux </h1>

<h2>Description</h2>
The research team at my organization needs to update the file permissions for certain files and directories within the projects directory. The permissions do not currently reflect the level of authorization that should be given. Checking and updating these permissions will help keep their system secure. To complete this task, I performed the following tasks:
<br />


<h2>Languages and Utilities Used</h2>

- <b>PowerShell</b> 
- <b>Diskpart</b>

<h2>Environments Used </h2>

- <b>Windows 10</b> (21H2)

<h2>Program walk-through:</h2>

<p align="center">
Check file and directory details: <br/>
 
 The following code demonstrates how I used Linux commands to determine the existing permissions set for a specific directory in the file system.
 <br/>
 <br/>
 <img src="https://i.imgur.com/dPlSonb.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 <br/>

The first line of the screenshot displays the command I entered, and the other lines display the output. The code lists all contents of the projects directory. I used the ls command with the -la option to display a detailed listing of the file contents that also returned hidden files. The output of my command indicates that there is one directory named drafts, one hidden file named .project_x.txt, and five other project files. The 10-character string in the first column represents the permissions set on each file or directory.
 
<p align="center">
Describe the permissions string: <br/>
 
 The 10-character string can be deconstructed to determine who is authorized to access the file and their specific permissions. The characters and what they represent are as follows: <br/>
- 1st character: This character is either a d or hyphen (-) and indicates the file type. If it’s a d, it’s a directory. If it’s a hyphen (-), it’s a regular file. <br/>
- 2nd-4th characters: These characters indicate the read (r), write (w), and execute (x) permissions for the user. When one of these characters is a hyphen (-) instead, it indicates that this permission is not granted to the user. <br/>
-	5th-7th characters: These characters indicate the read (r), write (w), and execute (x) permissions for the group. When one of these characters is a hyphen (-) instead, it indicates that this permission is not granted for the group. <br/>
-	8th-10th characters: These characters indicate the read (r), write (w), and execute (x) permissions for other. This owner type consists of all other users on the system apart from the user and the group. When one of these characters is a hyphen (-) instead, that indicates that this permission is not granted for other. <br/>

For example, the file permissions for project_t.txt are -rw-rw-r--. Since the first character is a hyphen (-), this indicates that project_t.txt is a file, not a directory. The second, fifth, and eighth characters are all r, which indicates that user, group, and other all have read permissions. The third and sixth characters are w, which indicates that only the user and group have write permissions. No one has execute permissions for project_t.txt.
 
<p align="center">
Change file permissions: <br/>
 
The organization determined that other shouldn't have write access to any of their files. To comply with this, I referred to the file permissions that I previously returned. I determined project_k.txt must have the write access removed for other. <br/>
The following code demonstrates how I used Linux commands to do this:
 <br/>
 <br/>
<img src="https://i.imgur.com/A0Qu5hb.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 <br/>
The first two lines of the screenshot display the commands I entered, and the other lines display the output of the second command. The chmod command changes the permissions on files and directories. The first argument indicates what permissions should be changed, and the second argument specifies the file or directory. In this example, I removed write permissions from other for the project_k.txt file. After this, I used ls -la to review the updates I made.

<p align="center">
Change file permissions on a hidden file: <br/>
 
The research team at my organization recently archived project_x.txt. They do not want anyone to have write access to this project, but the user and group should have read access. <br/>
The following code demonstrates how I used Linux commands to change the permissions:
<br/>
<br/>
 <img src="https://i.imgur.com/EPXXLNY.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br/>
The first two lines of the screenshot display the commands I entered, and the other lines display the output of the second command. I know .project_x.txt is a hidden file because it starts with a period (.). In this example, I removed write permissions from the user and group, and added read permissions to the group. I removed write permissions from the user with u-w. Then, I removed write permissions from the group with g-w, and added read permissions to the group with g+r. 
 
<p align="center">
Change directory permissions: <br/>
 
My organization only wants the researcher2 user to have access to the drafts directory and its contents. This means that no one other than researcher2 should have execute permissions.<br/>
The following code demonstrates how I used Linux commands to change the permissions:
<br/>
<br/>
 <img src="https://i.imgur.com/xdJrvGr.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 
<p align="center">
Summary: <br/>
 
I changed multiple permissions to match the level of authorization my organization wanted for files and directories in the projects directory. The first step in this was using ls -la to check the permissions for the directory. This informed my decisions in the following steps. I then used the chmod command multiple times to change the permissions on files and directories.
 <br/>
 <br/>

 
<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>
