---
title: Pack and Unpack
---
### ql.pack()
```python
ql.pack()
```
- If ql.archbit == 64 then ql.pack64 else ql.pack32

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


### ql.unpack()
```python
ql.unpack()
```
- If ql.archbit == 64 then ql.unpack64 else ql.unpack32

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
ql.pack16()
```
- pack for 16bit data
> - Pack with option "H", with endian check:
> - C Type: unsigned short 
> - Size: 2 bytes

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
- If ql.archbit == 64 then ql.pack64s else ql.pack32s

```python
ql.pack64s()
```
- packs for 64bit data
> - Pack with option "q":
> - C Type: long 
> - Size: 8 bytes

```python
ql.pack32s
```
- packs for 32bit data
> - Pack with option "i", with endian check:
> - C Type: int 
> - Size: 4 bytes


### ql.unpacks()
```python
ql.unpacks()
```
- If archbit == 64 then ql.unpack64s else ql.unpack32s

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


### ql.unpack32_ne()
```python
ql.unpack32_ne()
```
> - Unpack with option "i":
> - C Type: int 
> - Size: 4 bytes
