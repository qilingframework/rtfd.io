---
title: Memory
---

### Architectural stack operations
Qiling abstracts the architectural stack operations as follows:

Pop a value off the top of stack:
```python
value = ql.arch.stack_pop()
```

Push a value to the top of stack:
```python
ql.arch.stack_push(value)
```

Peek the value at a certain offset from the top without modifying the stack pointer:
Note: the offset may be either positive, negative or zero (to peek the top of stack)
```python
value = ql.arch.stack_read(offset)
```

Replace a value at a certain offset from the top without modifying the stack pointer:
Note: the offset may be either positive, negative or zero (to replace the top of stack)
```python
ql.arch.stack_write(offset, value)
```

# Memory subsystem
Represents the emulated memory space.

## Managing memory
Qiling offers several methods for managing the emulated memory space:

| Method            | Description
|:--                | :--
| `map`             | Map a memory region at a certain location so it become available for access
| `unmap`           | Reclaim a mapped memory region
| `unmap_all`       | Reclaim all mapped memory regions
| `map_anywhere`    | Map a memory region in an unspecified location
| `protect`         | Modify access protection bits of a mapped region (rwx)
| `find_free_space` | Find an available memory region
| `is_available`    | Query whether a memory region is available
| `is_mapped`       | Query whether a memory region is mapped

Note: `is_available` and `is_mapped` are not necessarily ooposites; when a memory region is _partially taken_ (mapped), both methods will return `False`.


### Mapping memory pages
Memory has to be mapped before it can be accessed. The `map` method binds a contiguous memory region at a specified location, and sets its access protection bits. A string label may be provided for easy identification on the mapping info table (see: `get_map_info`).

Synposys:
```python
ql.mem.map(addr: int, size: int, perms: int = UC_PROT_ALL, info: Optional[str] = None) -> None
```
Arguments:
- `addr` - requested mapping base address; should be on a page granularity (see: `pagesize`)
- `size` - mapping size in bytes; must be a multiplication of page size
- `perms` - protection bitmap; defines whether this memory range is readable, writeable and / or executable (optional, see: `UC_PROT_*` constants)
- `info` - sets a string label to the mapped range for easy identification (optional)

Returns: `None`

Raises: `QlMemoryMappedError` if the requested memory range is not entirely available


### Unmapping memory pages
Mapped memory regions may be reclaimed by unmapping them. The `unmap` method reclaims a memory region at a specified location. The unmapping functionality is not limited to compelte memory regions, and may be used for partial ranges as well.

Synposys:
```python
ql.mem.unmap(addr: int, size: int) -> None:
```
Arguments:
- `addr` - region base address to unmap
- `size` - region size in bytes

Returns: `None`

Raises: `QlMemoryMappedError` if the requested memory range is not entirely mapped





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
ql.mem.get_formatted_mapinfo()
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
