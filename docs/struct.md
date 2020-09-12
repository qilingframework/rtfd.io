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
