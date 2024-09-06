#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>

struct free_chunk // struct of the metadata of free chunk
{
	unsigned long Size;
	struct free_chunk *next;
	struct free_chunk *prev;
};

struct free_chunk *head = NULL;

const unsigned long metasz = 8;

unsigned long is_min_size(unsigned long size)
{
	// This function computes the size needed
	// including size requested + metadata size
	//+ padding
	unsigned long size_reqd = size + metasz;
	for (unsigned long int i = 0; i <= 7; i++)
	{
		if ((size_reqd + i) % 8 == 0)
		{
			size_reqd += i;
			break;
		}
	}
	if (size_reqd < 24)
	{
		size_reqd = 24;
	}
	return size_reqd;
}

unsigned long new_memory_needed(unsigned long size)
{
	// This function computes the minimum multiple
	// of 4MB chunk for size allocation
	unsigned long multiple = 1;
	unsigned long curr_size = 4 * 1024 * 1024;
	while (multiple * curr_size < size + metasz)
	{
		multiple++;
	}
	return (multiple * curr_size);
}

void *memalloc(unsigned long size)
{
	if (size == 0)
	{
		return NULL;
	}
	unsigned long min_size_reqd = is_min_size(size);
	struct free_chunk *curr = head;

	while (curr != NULL)
	{
		if (curr->Size >= min_size_reqd)
		{
			if (curr->Size - min_size_reqd < 24)
			{
				// This case happens when the size of the free
				// chunk and the required memory size differ by
				// less than 24
				if (curr->prev == NULL)
				{
					head = curr->next;
				}
				else
				{
					curr->prev->next = curr->next;
					if (curr->next != NULL)
					{
						curr->next->prev = curr->next;
					}
				}
				// storing size (metadata) of the allocated region in the
				// first 8 bytes
				unsigned long int *curr_ptr = (unsigned long int *)curr;
				(*curr_ptr) = curr->Size;
				return (void *)((void *)curr + metasz);
			}
			else
			{
				// This case happens when the size of the free
				// chunk and the required memory size differ by
				// greater than or equal to 24
				struct free_chunk *new_chunk = (struct free_chunk *)((void *)curr + min_size_reqd);
				new_chunk->Size = curr->Size - min_size_reqd;
				new_chunk->prev = NULL;
				new_chunk->next = head;
				if (head != NULL)
				{
					head->prev = new_chunk;
				}
				if (curr->prev != NULL)
				{
					curr->prev->next = curr->next;
				}
				if (curr->next != NULL)
				{
					curr->next->prev = curr->prev;
				}
				head = new_chunk;
				// storing size (metadata) of the allocated region in the
				// first 8 bytes
				unsigned long int *curr_ptr = (unsigned long int *)curr;
				(*curr_ptr) = min_size_reqd;
				return (void *)((void *)curr + metasz);
			}
		}
		curr = curr->next;
	}
	if (curr == NULL)
	{
		// If no suitable free chunk found, memory is requested
		// from the OS using mmap()
		unsigned long new_mem_needed = new_memory_needed(size);
		void *new_chunk = (void *)mmap(NULL, new_mem_needed, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (new_chunk == MAP_FAILED)
		{
			return NULL; // mmap() failed
		}
		if (new_mem_needed - min_size_reqd < 24)
		{
			// This case heppens when size of the memory chunk
			// and size needed differ by less than 24
			unsigned long int *curr_ptr = (unsigned long int *)new_chunk;
			*(curr_ptr) = new_mem_needed;
			void *return_ptr = (void *)((void *)new_chunk + metasz);
			return return_ptr;
		}
		else
		{
			// This case heppens when size of the memory chunk
			// and size needed differ by greater than or equal to 24
			unsigned long int *curr_ptr = (unsigned long int *)new_chunk;
			*(curr_ptr) = min_size_reqd; // metadata of alocated chunk
			void *return_ptr = (void *)((void *)new_chunk + metasz);
			// storing the metadata of the free chunk in the first 24 bytes
			//(8+8+8 each for size, next and previous pointers) of free chunk
			struct free_chunk *new_free_chunk = (struct free_chunk *)(new_chunk + min_size_reqd);
			new_free_chunk->Size = new_mem_needed - min_size_reqd;
			new_free_chunk->next = head;
			new_free_chunk->prev = NULL;
			if (head != NULL)
			{
				head->prev = new_free_chunk;
			}
			head = new_free_chunk;
			return return_ptr;
		}
	}
}

int memfree(void *ptr)
{
	if (ptr == NULL)
	{
		return -1; // Nothing to free
	}

	void *al_chunk = ((void *)ptr - metasz);
	// getting the metadata of the allocated chunk
	unsigned long *al_chunk_ptr = (unsigned long *)al_chunk;
	unsigned long chunk_size = *(al_chunk_ptr);
	struct free_chunk *allocated_chunk = (struct free_chunk *)al_chunk;
	allocated_chunk->Size = chunk_size;
	allocated_chunk->prev = NULL;
	allocated_chunk->next = NULL;

	// These two pointers (before_chunk and after_chunk)
	// are used to check if the region to be freed has
	// adjacently connected free regions
	struct free_chunk *before_chunk = NULL;
	struct free_chunk *after_chunk = NULL;
	struct free_chunk *curr = head;

	while (curr != NULL)
	{
		if ((void *)curr + curr->Size == allocated_chunk)
		{
			before_chunk = curr;
		}
		if ((void *)allocated_chunk + allocated_chunk->Size == curr)
		{
			after_chunk = curr;
		}
		curr = curr->next;
	}

	if (before_chunk == NULL && after_chunk == NULL)
	{
		// Case 1: contiguous memory chunks on
		// left and right both are not free
		allocated_chunk->next = head;
		allocated_chunk->prev = NULL;
		if (head != NULL)
		{
			head->prev = allocated_chunk;
		}
		head = allocated_chunk;
	}
	else if (before_chunk != NULL && after_chunk == NULL)
	{
		// Case 2: contiguous memory chunk only on
		// left is free

		// coalescing left chunk + region to be freed
		before_chunk->Size = before_chunk->Size + allocated_chunk->Size;
		if (before_chunk->prev != NULL)
		{
			before_chunk->prev->next = before_chunk->next;
		}
		if (before_chunk->next != NULL)
		{
			before_chunk->next->prev = before_chunk->prev;
		}
		before_chunk->next = head;
		before_chunk->prev = NULL;
		if (head != NULL)
		{
			head->prev = before_chunk;
		}
		head = before_chunk;
	}
	else if (before_chunk == NULL && after_chunk != NULL)
	{
		// Case 3: contiguous memory chunk only on
		// right is free

		// coalescing right chunk + region to be freed
		allocated_chunk->Size = allocated_chunk->Size + after_chunk->Size;
		if (after_chunk->next != NULL)
		{
			after_chunk->next->prev = after_chunk->prev;
		}
		if (after_chunk->prev != NULL)
		{
			after_chunk->prev->next = after_chunk->next;
		}
		allocated_chunk->next = head;
		allocated_chunk->prev = NULL;
		if (head != NULL)
		{
			head->prev = allocated_chunk;
		}
		head = allocated_chunk;
	}
	else if (before_chunk != NULL && after_chunk != NULL)
	{
		// Case 4: contiguous memory chunk on both sides
		// are free

		if (before_chunk->prev != NULL)
		{
			before_chunk->prev->next = before_chunk->next;
		}
		if (before_chunk->next != NULL)
		{
			before_chunk->next->prev = before_chunk->prev;
		}
		// coalescing left chunk + region to be freed + right chunk
		before_chunk->Size = before_chunk->Size + allocated_chunk->Size + after_chunk->Size;

		if (after_chunk->prev != NULL)
		{
			after_chunk->prev->next = after_chunk->next;
		}
		if (after_chunk->next != NULL)
		{
			after_chunk->next->prev = after_chunk->prev;
		}
		before_chunk->next = head;
		if (head != NULL)
		{
			head->prev = before_chunk;
		}
		head = before_chunk;
	}

	return 0; // Successfully freed the memory
}
