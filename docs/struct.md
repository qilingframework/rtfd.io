---
title: Pack and Unpack
---
### ql.pack()
```python
ql.pack()
```
- depends on ql.archbit, ql.pack64 for 64-bit and so on

```python
ql.pack64()
```
- pack for 64bit data
> - Pack with option "Q":
> - C Type: unsigned long long 
> - Size: 8 bytes

```python
ql.pack32()
```
- pack for 32bit data
> - Pack with option "I", with endian check:
> - C Type: unsigned int 
> - Size: 4 bytes

```python
ql.pack16()
```
- pack for 16bit data
> - Pack with option "H", with endian check:
> - C Type: unsigned short 
> - Size: 2 bytes

### ql.unpack()
```python
ql.unpack()
```
- depends on ql.archbit, ql.unpack64 for 64-bit and so on 

```python
ql.upack64()
```
- unpack for 64bit data
> - Unpack with option "Q":
> - C Type: unsigned long long 
> - Size: 8 bytes

```python
ql.unpack32()
```
- unpack for 32bit data
> - Unpack with option "I", with endian check:
> - C Type: unsigned int 
> - Size: 4 bytes

```python
ql.unpack16()
```
- unpack for 16bit data
> - Unpack with option "H", with endian check:
> - C Type: unsigned short 
> - Size: 2 bytes

### ql.packs()
```python
ql.packs()
```
- signed packing
- depends on ql.archbit, ql.pack64s for 64-bit and so on 

```python
ql.pack64s()
```
- packs for 64bit data
> - Pack with option "q":
> - C Type: long 
> - Size: 8 bytes

```python
ql.pack32s()
```
- packs for 32bit data
> - Pack with option "i", with endian check:
> - C Type: int 
> - Size: 4 bytes

```python
ql.pack16s()
```
- packs for 16bit data
> - Unpack with option "h", with endian check:
> - C Type: short
> - Size: 2 bytes

### ql.unpacks()
```python
ql.unpacks()
```
- signed unpacking
- depends on ql.archbit, ql.unpack64s for 64-bit and so on 

```python
ql.unpack64s()
```
- unpacks for 64bit data
> - Unpack with option "q":
> - C Type: long 
> - Size: 8 bytes

```python
ql.unpack32s()
```
- unpacks for 32bit  data
> - Unpack with option "i", with endian check:
> - C Type: int 
> - Size: 4 bytes

```python
ql.unpack16s()
```
- packs for 16bit data
> - Unpack with option "h", with endian check:
> - C Type: short
> - Size: 2 bytes

--- 

## Custom Pack & Unpack
Qiling has some built-in functions to handle Pack & UnPack of the memory, but if you need more flexibility, you should
use the python “struct” lib.
For someone, the lib struct call recalls the complex memory structure from *C ANSI* defined by the struct keyword,
and yes, you are right.

### struc lib
> https://docs.python.org/3/library/struct.html#module-struct 

> Byte Order, Size, and Alignement: https://docs.python.org/3/library/struct.html#byte-order-size-and-alignment

> Format Characters: https://docs.python.org/3/library/struct.html#format-characters

If we take a look at the example below, we can see that the *unpack* function accepts two parameters, the first of which
is our format string:

```python
record = b'raymond   \x32\x12\x08\x01\x08'
name, serialnum, school, gradelevel = unpack('<10sHHb', record)
```
`<` -->  *little-endian*

`10s` --> `raymond***` --> 10 x `char[]`

`H` --> *unsigned short*

`H` --> *unsigned short*

`b` --> *signed char*

### understand the right structure
To understand how a complex data structure is composed in memory and to be able to pack and/or unpack it, we can find ourselves in front of two scenarios:
- Know structure (os, shared software, standard lib)
- Unknown structure (close source software, custom lib)

As far as the known structures are concerned, Google or a few books will absolve the job, but for the unknown ones,
you should prepare a decompiler (IDA, Ghidra, r2); you will have to get your hands dirty yourself.


### example
#### Info
> - Target: Netgear 6220
> - CPU-Arch: mips32el
> - Endian: el -> endian little
> - API: bind
> - API-Info: https://man7.org/linux/man-pages/man2/bind.2.html
> - Struct: sockaddr_in
> - Struct-Info: https://man7.org/linux/man-pages/man7/ip.7.html (From bind page, AF_INET)

#### Structure
```c
struct sockaddr_in {
   sa_family_t    sin_family; /* address family: AF_INET */
   in_port_t      sin_port;   /* port in network byte order */
   struct in_addr sin_addr;   /* internet address */
};

/* Internet address. */
struct in_addr {
  uint32_t       s_addr;     /* address in network byte order */
};
```

#### Code
```python
def my_bind(ql, *args, **kw):
    params = ql.os.resolve_fcall_params({
        'fd': UINT,
        'addr': POINTER,
        'addrlen': UINT
    })

    bind_fd = params['fd']
    bind_addr = params['addr']
    bind_addrlen = params['addrlen']

    # read from memory (start_address, len)
    data = ql.mem.read(bind_addr, bind_addrlen)
    # custom unpack (your own ql.unpack) of a C struct from memory
    # https://linux.die.net/man/7/ip -> struct
    sin_family = struct.unpack("<h", data[:2])[0] or ql.os.fd[bind_fd].family
    # little-endian short -> format_string -> https://docs.python.org/3/library/struct.html#format-strings
    port, host = struct.unpack(">HI", data[2:8])
    # big-endian unsigned short, unsigned int -> format_string
    return 0
```
If you're wondering why even though the architecture is little-endian in the second string format, the big-endian
notation has been used, remember that everything about network stacks is big-endian (as indicated on the struct library
page); double-check the structure reported above and notice the comments.

> Full code: https://github.com/qilingframework/qiling/blob/master/examples/netgear_6220_mips32el_linux.py
