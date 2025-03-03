# Memory Allocator

This project is a custom memory allocator implemented in C as part of an academic assignment. The allocator provides functionality similar to `malloc`, `calloc`, `realloc`, and `free`, but manages memory manually using a custom heap structure.

## Features

- **Dynamic Memory Allocation** – Implements `malloc` to allocate memory from a pre-allocated heap.
- **Memory Reallocation** – Supports `realloc` to resize previously allocated blocks.
- **Zero-Initialized Allocation** – Implements `calloc`, ensuring memory is set to zero.
- **Memory Deallocation** – Handles `free`, releasing allocated memory and preventing leaks.
- **Coalescing Free Blocks** – Merges adjacent free blocks to optimize memory usage.
- **Custom Heap Management** – Simulates a memory pool instead of relying on system calls.
- **Fragmentation Reduction** – Implements strategies to minimize memory fragmentation.

## Implementation Details

- Uses a **linked list** to track allocated and free memory blocks.
- Metadata stored in each block for efficient memory management.
- Supports **best-fit** or **first-fit** allocation strategies (if applicable).
- Ensures proper memory alignment for performance and stability.
