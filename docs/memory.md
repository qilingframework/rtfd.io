---
title: Memory
---
### Stack related
- Pop
```python
ql.stack_pop(offset)
```

- push
```python
ql.stack_push(offset)
```

- Read
```python
ql.stack_read(offset)
```

- Write
```python
ql.stack_write(offset, data)
```

### Search bytes pattern from memory
- Search for a pattern from entire memory
```python
address = ql.mem.search(b"\xFF\xFE\xFD\xFC\xFB\xFA")
```
- Search for a pattern from entire memory range
```python
address = ql.mem.search(b"\xFF\xFE\xFD\xFC\xFB\xFA", begin= 0x1000, end= 0x2000)
```

### Read from a memory address
```python
ql.mem.read(address, size)
```

### Write to a memory address
```python
ql.mem.write(address, data)
```

### Map a memory area
map a memory before writing into it. Info can be empty.
```python
ql.mem.map(addr,size,info = [my_first_map])
```

Address:

You need to align the memory offset and address for mapping.

`addr//size*size` -> `0x7fefc9e0//4096*4096`

Size:

The amounts of memory that should be mapped

> This parameter is OS dependant; If you use a linux system, consider at least a multiple of 4096 for alignment


example (Linux):
```python
[..]
def memory_fix(ql, access, addr, size, value):
    ql.nprint("[_] Mapping "+str(size)+" bytes at "+hex(addr)+" | access: "+ str(access)+" | value: "+ str(value))
    ql.mem.map(addr//4096*4096, 4096)
    ql.mem.write(addr, struct.pack(">I",value)) # memory packing is OS dependant
    return 

[...]
ql.hook_mem_unmapped(memory_fix)
[...]
```

See **qiling/loader/elf.py** for a proper mapping example

### read and write string
to read a string from memory
```python
ql.mem.string(address)
```

to write a string to memory
```python
ql.mem.string(address, "stringwith")
```

### Show all the mapped area
```python
ql.mem.show_mapinfo()
```

### Unmap a mapped area
```python
ql.mem.unmap(self, addr, size) 
```

### Unmap all mapped area
```python
ql.mem.unmap_all()
```

### find a free space
Find a specific free space size.
```python
ql.mem.find_free_space(size)
```    

### check for availablity
The main function of is_available is to determine 
whether the memory starting with addr and having a size of length can be used for allocation.
If it can be allocated, returns True.
If it cannot be allocated, it returns False.
```python
ql.mem.is_available(addr, size)
```

### check for is the memory area being mapped
The main function of is_mmaped is to determine  whether the memory starting with addr and size has been mapped.
Returns true if it has already been allocated. If unassigned, returns False.
```python
ql.mem.is_mapped(addr, size)
```

### Find a matching size of unmapped usable space
Finds a region of memory that is free, larger than 'size' arg, and aligned.
```python
ql.mem.find_free_space(size, min_addr=0, max_addr = 0, alignment=0x10000)
```

### Find a matching size of unmapped usable space and map it
Maps a region of memory with requested size, within the addresses specified. The size and start address will respect the alignment.
```python
ql.mem.map_anywhere(size)
```
