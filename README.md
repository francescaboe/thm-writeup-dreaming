# THM write-up - [Dreaming](https://tryhackme.com/r/room/dreaming)

![intro](https://github.com/francescaboe/thm-writeup-dreaming/blob/main/assets/Pasted%20image%2020241218143850.png)

## The intro
Difficult level: **Easy**

Estimated time to complete: **45 mins** 



Let's see what we're working with, not much at all to be honest, but who needs long introductions?

_Solve the riddle that dreams have woven._
Mysterious, don't we like riddles, and we do like dreaming.

_While the king of dreams was imprisoned, his home fell into ruins. 
Can you help Sandman restore his kingdom?_

Let's go save the kingdom and maybe turn it into a democracy.

## The hunt
Let's start with some good old Reconnaissance with the OG `nmap`
`nmap -p- -T4 <target-ip>`
	because no port left behind (`-p-`)
	and we don't have time to be stealthy (`-T4`) 
	![[Pasted image 20241219104314.png]]
Would you look at that, we got ourselves an open http port and an ssh one, let's see what's at that address from our bowsers.

Navigate to `<target-ip>` from firefox: looks like we are dealing with an Apache2 server, let's keep it in mind for the future.
![[Pasted image 20241219104744.png]]

Meanwhile let's see what else we can find, `gobuster` to the rescue!
`gobuster dir -u <target-ip> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -r`
	append `dir`
	to our address `-u <target-ip>`
	use the directory list provided `-w <provided-list>`
	and follow the redirections `-r`
Looks like we got an `/app` directory, let's see what's there
![[Pasted image 20241219105402.png]]
`pluck-4.7.13` what's that? let's google it!
mmh first results look promising, who doesn't like [Remote Code execution vulnerability](https://www.exploit-db.com/exploits/49909)? 
![[Pasted image 20241219105634.png]]
```
Description:
A file upload restriction bypass vulnerability in Pluck CMS before 4.7.13 allows an admin
privileged user to gain access in the host through the "manage files" functionality,
which may result in remote code execution.
```
Let's go!
Firstly, let's go into the pluck folder:
![[Pasted image 20241219105924.png]]

Following the exploit instructions let's click on "admin" and land on the login page, this is what we find: a form input for a password, no username, a commented `bogus` input? 
![[Pasted image 20241218161831.png]]

let's `hydra` the `fuzz` out of this:
`hydra -l admin -P /usr/share/wordlists/rockyou.txt <target-ip> http-post-form "/app/pluck-4.7.13/login.php:cont1=^PASS^&bogus=&submit=Log+in:F=Invalid" -V`

![[Pasted image 20241218162034.png]]
password is `password`, I could have guessed that!
Ok we are in, let's follow the exploit: we can go to pages > manage files and upload a shell
![[Pasted image 20241219110642.png]]
and we see
![[Pasted image 20241219110904.png]]
let's get our usual php shell from the attack box, or ask AI to create one, whatever is easier:
`cat /usr/share/webshells/php/php-reverse-shell.php > myshell.php.phar`
`nano myshell.php.phar`
then we add our attack box ip and a random port, I like to go for `666` - for no particular reason.
let's also start ourselves an netcat listener at our `666` port
`nc -lvnp 666`
**Note**: if we try to upload a file with just `.php`  extension, `.txt` extension is appended, ruining all the fun, that .`phar` let's us bypass that.

Now, let's navigate to the shell, we do so by clicking on the lens:
![[Pasted image 20241219112116.png]]

Aaaand we're in!
![[Pasted image 20241219111823.png]]
But this shell is lame, let's upgrade it and make our lives a bit easier:
`python3 -c 'import pty; pty.spawn("/bin/bash")'`

Now more reconnaissance, or, as I like to call it, increasingly desperate search for SOMETHING
`whoami` > `www-data` laaaame
- `cat /etc/passwd`
	![[Pasted image 20241218235644.png]]

cool so we have lucien, death and morpheus, incidentally the owners of the flags we need to find. 
`cat /home/lucien/lucien_flag` > permission denied
and same goes for the other two. 
One thing is clear, we need to **ESCALATE PRIVILEDGE**.
Let's keep looking: aimlessly go around the server and look for anything interesting, despair, pray the cybersecurity Gods, curse the cybersecurity gods, talk to the AI, google  franticly, ask for a hint, go take a nap.
![[Pasted image 20241219112959.png]]

`ls -la opt`
![[Pasted image 20241219113103.png]]
curious, 2 python scripts we have reading permissions for: let's read `test.py`, ah-ha! 
![[Pasted image 20241219113454.png]]
if it isn't a password for `lucien`!
`HeyLucien#@1999!`
Let's assume lucien's identity immediately! `su lucien`
Go read the damn flag! `cat /home/lucien/lucien_flag.txt`
1. **What is the Lucien Flag?**  
	_THM{TH3_L1BR4R14N}_

2. **What is the Death Flag?**  
Now that we have a password and we know we have an `ssh` port open, let's try and get ourselves a fully functioning terminal, this reverse-shell served us well but it's time to upgrade: from a new terminal tab
`ssh lucien@<target-ip>`
and it worked!
Let' see what we can do as lucien `sudo -l`

```
User lucien may run the following commands on dreaming:
(death) NOPASSWD: /usr/bin/python3 /home/death/getDreams.py
```

if we `ls -l` in `death`'s folder we see
![[Pasted image 20241219114207.png]]
so we can use python to run this getDreams.py script as `death`, but we can't edit it nor open. 

- `sudo -u death /usr/bin/python3 /home/death/getDreams.py`
![[Pasted image 20241219000931.png]]

uh, I just remembered, wasn't there a python script with the same name in `/opt` that we had reading permissions for? let's go see what is the deal with that


3. **What is the Morpheus Flag?**
