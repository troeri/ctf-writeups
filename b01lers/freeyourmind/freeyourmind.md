# Free Your Mind - PWN (200pts)

```c
#include <stdio.h>
#include <unistd.h>

char shellcode[16];

int main() {
    char binsh[8] = "/bin/sh";

    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);

    printf("I'm trying to free your mind, Neo. But I can only show you the door\
. You're the one that has to walk through it.\n");
    read(0, shellcode, 16);

    ((void (*)()) (shellcode))();
}
```

## Investigation
This challenge is more a task of avoiding constraints rather than identifying a weakness and exploiting it. From the source code we can see that the binary reads input data, stores it in the array declared as shellcode and then attempts to run this as a function. Assuming we can input a working shellcode to the binary, it should spawn a shell. Since the pointer is provided by the source code, we don't have to worry about ASLR for this challenge.

But there is a problem - The allocated memory for shellcode is only 16 bytes. 

## Solution


we can see that the string '/bin/sh' is stored in the binary and a declaration of 16 byte reserved for shellcode
