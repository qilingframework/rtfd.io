---
title: Memory
---


### Stack realted
- Pop
```
ql.stack_pop(value)
```

- push
```
ql.stack_push(value)
```

- Read
```
ql.stack_read(address)
```

- Write
```
ql.stack_write(value, address)
```

### Read from a memory address
```
ql.mem.read(address)
```

### Write to a memory address
```
ql.mem.read(address, data)
```

### Map a memory area
map a memory before writing into it. Info can be empty
```
ql.mem.map(addr,size,info = [my_first_map])
```

### read and write string
to read a string from memory
```
ql.mem.string(address)
```

to write a string to memory
```
ql.mem.string(address, "stringwith")
```

### Show all the mapped area
```
ql.mem.show_mapinfo()
```

### Unmap a mapped area
```
ql.mem.unmap(self, addr, size) 
```

### Unmap all mapped area
```
ql.mem.unmap_all()
```

### find a free space
Find a specific free space size.
```
ql.mem.find_free_space(size)
```    

### check for availablity
The main function of is_available is to determine 
whether the memory starting with addr and having a size of length can be used for allocation.
If it can be allocated, returns True.
If it cannot be allocated, it returns False.
```
ql.mem.is_available(addr, size)
```

### check for is the memory area being mapped
The main function of is_mmaped is to determine  whether the memory starting with addr and size has been mapped.
Returns true if it has already been allocated. If unassigned, returns False.
```
ql.mem.is_mapped(addr, size)
```

### Find a matching size of unmapped usable space
Finds a region of memory that is free, larger than 'size' arg, and aligned.
```
ql.mem.find_free_space(size, min_addr=0, max_addr = 0, alignment=0x10000)
```

### Find a matching size of unmapped usable space and map it
Maps a region of memory with requested size, within the addresses specified. The size and start address will respect the alignment.
```
ql.mem.map_anywhere(size)
```