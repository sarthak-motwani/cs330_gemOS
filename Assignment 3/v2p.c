#include <types.h>
#include <mmap.h>
#include <fork.h>
#include <v2p.h>
#include <page.h>

/*
 * You may define macros and other helper functions here
 * You must not declare and use any static/global variables
 * */

#define PAGE_SIZE 4096
#define LEVEL_BITS 0x1FF
#define OFFSET_BITS 0xFFF
#define PTE_SIZE 8 // bytes = 64 bits

int nearest_page_num(int length)
{
    int factor = 1;
    while (factor * PAGE_SIZE < length)
    {
        factor++;
    }
    return factor;
}

// function to add a new vm_area next to a vm_area

void add_new_vm(unsigned long addr, struct vm_area *vm_temp, long actual_sz, int prot)
{
    struct vm_area *vm_new = (struct vm_area *)os_alloc(sizeof(struct vm_area));
    if (addr == 0)
    {
        vm_new->vm_start = vm_temp->vm_end;
    }
    else
    {
        vm_new->vm_start = addr;
    }
    vm_new->vm_end = (vm_new->vm_start) + actual_sz;
    vm_new->access_flags = prot;
    vm_new->vm_next = vm_temp->vm_next;
    vm_temp->vm_next = vm_new;
    return;
}

// function to allocate/expand a vm_area when vm_temp->vm_next is NULL
long new_vm_at_end(unsigned long addr, struct vm_area *vm_temp, int prot, unsigned long actual_sz)
{
    if ((addr == 0 || addr == vm_temp->vm_end) && prot == vm_temp->access_flags)
    {
        // coalescing if prot is same
        long ret_addr = (long)vm_temp->vm_end;
        vm_temp->vm_end = (vm_temp->vm_end) + actual_sz;
        return ret_addr;
    }
    else
    {
        // prot is different, not coalescing
        add_new_vm(addr, vm_temp, actual_sz, prot);
        stats->num_vm_area++;
        long ret_addr = (long)vm_temp->vm_next->vm_start;
        return ret_addr;
    }
}

// function to allocate/expand a vm_area in between two vm_areas
long new_vm_in_between(unsigned long addr, struct vm_area *vm_temp, int prot, unsigned long actual_sz)
{
    long vm_gap = vm_temp->vm_next->vm_start - vm_temp->vm_end;
    if (addr != 0)
    {
        vm_gap = vm_temp->vm_next->vm_start - addr;
    }
    //   printk("vmgap: %x\n", vm_gap);
    if ((addr == 0 || addr == vm_temp->vm_end) &&
        (prot == vm_temp->access_flags) &&
        ((vm_gap > actual_sz) || prot != vm_temp->vm_next->access_flags))
    {
        // printk("case 1\n");
        // coalescing if prot is same only for vm_temp and vm_new
        long ret_addr = (long)vm_temp->vm_end;
        vm_temp->vm_end = (vm_temp->vm_end) + actual_sz;
        return ret_addr;
    }

    // coelescing all the three
    else if ((addr == 0 || addr == vm_temp->vm_end) &&
             vm_gap == actual_sz && prot == vm_temp->access_flags &&
             prot == vm_temp->vm_next->access_flags)
    {
        //  printk("case 2\n");
        long ret_addr = (long)vm_temp->vm_end;
        // we also need to de_alloc vm_temp->next
        vm_temp->vm_end = vm_temp->vm_next->vm_end;
        struct vm_area *vm_to_free = vm_temp->vm_next;
        vm_temp->vm_next = vm_temp->vm_next->vm_next;
        // not handling memory related errors as of now
        os_free((void *)vm_to_free, sizeof(struct vm_area));
        stats->num_vm_area--;
        return ret_addr;
    }

    // coalescing vm_new and vm_temp->next (last two)
    else if (vm_gap == actual_sz && prot != vm_temp->access_flags &&
             prot == vm_temp->vm_next->access_flags)
    {
        // printk("case 3\n");
        long ret_addr;
        if (addr == 0)
        {
            ret_addr = (long)vm_temp->vm_end;
            vm_temp->vm_next->vm_start = (vm_temp->vm_end);
        }
        else
        {
            ret_addr = (long)addr;
            vm_temp->vm_next->vm_start = addr;
        }
        return ret_addr;
    }
    else
    {
        //    printk("case 4\n");
        // prot is different of vm_new with temp and vm_temp->next, not coalescing
        add_new_vm(addr, vm_temp, actual_sz, prot);
        stats->num_vm_area++;
        long ret_addr = (long)vm_temp->vm_end;
        if (addr != 0)
        {
            ret_addr = (long)addr;
        }
        return ret_addr;
    }
}

// given an address, it frees the pfn and updates the corresponding pte entry(s)
void free_pfn(struct exec_context *current, u64 addr)
{
    u64 pgdb = (u64)current->pgd; // virtual address of pgd level of page table
    u64 pgdb_v = (u64)osmap(pgdb);
    u64 level_1_bits = ((addr >> 39) & LEVEL_BITS);
    u64 level_2_bits = ((addr >> 30) & LEVEL_BITS);
    u64 level_3_bits = ((addr >> 21) & LEVEL_BITS);
    u64 level_4_bits = ((addr >> 12) & LEVEL_BITS);
    u64 offset = (addr & OFFSET_BITS);
    // level 1 -> pgd
    u64 pgd_entry_addr = pgdb_v + (u64)(level_1_bits * PTE_SIZE);
    u64 pgd_entry = *((u64 *)pgd_entry_addr);
    int present_bit1 = (pgd_entry & 1);
    if (present_bit1 == 1)
    {
        u64 pud_pg_addr = ((u64)(*((u64 *)pgd_entry_addr)) >> 12);
        u64 pud_pg_vaddr = (u64)(osmap(pud_pg_addr));
        u64 pud_entry_addr = pud_pg_vaddr + (u64)(level_2_bits * PTE_SIZE);
        u64 pud_entry = *((u64 *)pud_entry_addr);
        int present_bit2 = (pud_entry & 1);

        if (present_bit2 == 1)
        {
            u64 pmd_pg_addr = ((u64)(*((u64 *)pud_entry_addr)) >> 12);
            u64 pmd_pg_vaddr = (u64)(osmap(pmd_pg_addr));
            u64 pmd_entry_addr = pmd_pg_vaddr + (u64)(level_3_bits * PTE_SIZE);
            u64 pmd_entry = *((u64 *)pmd_entry_addr);
            int present_bit3 = (pmd_entry & 1);

            if (present_bit3 == 1)
            {
                u64 pte_pg_addr = ((u64)(*((u64 *)pmd_entry_addr)) >> 12);
                u64 pte_pg_vaddr = (u64)(osmap(pte_pg_addr));
                u64 pte_entry_addr = pte_pg_vaddr + (u64)(level_4_bits * PTE_SIZE);
                u64 pte_entry = *((u64 *)pte_entry_addr);
                int present_bit4 = (pte_entry & 1);

                if (present_bit4 == 1)
                {
                    u64 user_pg_addr = ((u64)(*((u64 *)pte_entry_addr)) >> 12);
                    put_pfn((u32)user_pg_addr);
                    s8 pfn_refcount = get_pfn_refcount((u32)user_pg_addr);
                    if (pfn_refcount == 0)
                    {
                        os_pfn_free(USER_REG, user_pg_addr);
                        *((u64 *)pte_entry_addr) = 0;
                    }
                }
            }
        }
    }
}

// function to free any allocated pfns between this region
// this region is a single vm_area/ a part of cm_area
void free_pfn_from_vma(struct exec_context *current, u64 start_addr, u64 end_addr)
{
    int num_pages = (end_addr - start_addr) / PAGE_SIZE;
    for (int i = 0; i < num_pages; i++)
    {
        free_pfn(current, start_addr + i * PAGE_SIZE);
    }
}

// given a page table va, it goes through all the offsets and returns 1 if any entry is write, else returns 0
int page_entry_prots(u64 entry_addr)
{
    //   printk("function entering page_entry_prots entry_addr %x\n", entry_addr);
    u64 temp_addr = entry_addr;
    int total_offsets = 512;
    int is_write = 0;
    for (int i = 0; i < total_offsets; i++)
    {
        temp_addr = entry_addr + (i * PTE_SIZE);
        u64 curr_entry = *((u64 *)temp_addr);
        int present_bit = (curr_entry & 1);
        if (present_bit == 1)
        {
            int access_bit = (curr_entry >> 3) & 1;
            if (access_bit == 1)
            {
                is_write = 1;
                break;
            }
        }
    }
    if (is_write)
    {
        return 1;
    }
    return 0;
}

// given an address, this function will change the access flags of each level
void modify_prot_pfn(struct exec_context *current, u64 addr, int access_flags)
{
    int rw_bit = 0;
    if (access_flags == (PROT_READ | PROT_WRITE))
    {
        rw_bit = 1;
    }
    //   printk("rw_bit: %d, access_flags: %d\n", rw_bit, access_flags);
    u64 pgdb = (u64)current->pgd; // virtual address of pgd level of page table
    u64 pgdb_v = (u64)osmap(pgdb);
    u64 level_1_bits = ((addr >> 39) & LEVEL_BITS);
    u64 level_2_bits = ((addr >> 30) & LEVEL_BITS);
    u64 level_3_bits = ((addr >> 21) & LEVEL_BITS);
    u64 level_4_bits = ((addr >> 12) & LEVEL_BITS);
    u64 offset = (addr & OFFSET_BITS);
    // level 1 -> pgd
    u64 pgd_entry_addr = pgdb_v + (u64)(level_1_bits * PTE_SIZE);
    u64 pgd_entry = *((u64 *)pgd_entry_addr);
    int present_bit1 = (pgd_entry & 1);
    if (present_bit1 == 1)
    {
        u64 pud_pg_addr = ((u64)(*((u64 *)pgd_entry_addr)) >> 12);
        u64 pud_pg_vaddr = (u64)(osmap(pud_pg_addr));
        u64 pud_entry_addr = pud_pg_vaddr + (u64)(level_2_bits * PTE_SIZE);
        u64 pud_entry = *((u64 *)pud_entry_addr);
        int present_bit2 = (pud_entry & 1);

        if (present_bit2 == 1)
        {
            u64 pmd_pg_addr = ((u64)(*((u64 *)pud_entry_addr)) >> 12);
            u64 pmd_pg_vaddr = (u64)(osmap(pmd_pg_addr));
            u64 pmd_entry_addr = pmd_pg_vaddr + (u64)(level_3_bits * PTE_SIZE);
            u64 pmd_entry = *((u64 *)pmd_entry_addr);
            int present_bit3 = (pmd_entry & 1);

            if (present_bit3 == 1)
            {
                u64 pte_pg_addr = ((u64)(*((u64 *)pmd_entry_addr)) >> 12);
                u64 pte_pg_vaddr = (u64)(osmap(pte_pg_addr));
                u64 pte_entry_addr = pte_pg_vaddr + (u64)(level_4_bits * PTE_SIZE);
                u64 pte_entry = *((u64 *)pte_entry_addr);
                int present_bit4 = (pte_entry & 1);
                //   printk("pte entry before: %x\n", pte_entry);
                if (present_bit4 == 1)
                {
                    //   printk("Code reaching here %x\n", addr);
                    u64 user_pg_addr = ((u64)(*((u64 *)pte_entry_addr)) >> 12);
                    u64 last3_bits = (pte_entry) & 7;
                    u64 modified_pte_e = pte_entry >> 4;

                    int ref_count = get_pfn_refcount((u32)user_pg_addr);
                    if (rw_bit == 1 && ref_count == 1)
                    {
                        //   printk("pte_entry rw is made 1\n");
                        *((u64 *)pte_entry_addr) = ((modified_pte_e << 4) | 8) | last3_bits;
                        asm volatile("invlpg (%0);" ::"r"(addr) : "memory");
                    }
                    else
                    {
                        //   printk("pte_entry rw is made 0\n");
                        *((u64 *)pte_entry_addr) = (modified_pte_e << 4) | last3_bits;
                        asm volatile("invlpg (%0);" ::"r"(addr) : "memory");
                    }
                    u64 pte_entry = *((u64 *)pte_entry_addr);
                    //   printk("pte entry after: %x\n", pte_entry);
                    //   printk("pte_entry_addr: %x\n", pte_entry_addr);
                    //   printk("pte_pg_addr: %x\n", pte_pg_addr);
                    // level 3
                    int pmd_entry_prots = page_entry_prots(pte_pg_vaddr);
                    // all reads
                    u64 prot_flag = 0xFFFFFFFFFFFFFFF7;

                    if (pmd_entry_prots == 0)
                    {
                        //    printk("pmd_entry rw is made 0\n");
                        *((u64 *)pmd_entry_addr) = (*((u64 *)pmd_entry_addr)) & prot_flag;
                        asm volatile("invlpg (%0);" ::"r"(addr) : "memory");
                    }
                    else
                    {
                        if (ref_count == 1)
                        {
                            //   printk("pmd_entry rw is made 1\n");
                            *((u64 *)pmd_entry_addr) = (*((u64 *)pmd_entry_addr)) | 8;
                            asm volatile("invlpg (%0);" ::"r"(addr) : "memory");
                        }
                    }

                    // level 2
                    int pud_entry_prots = page_entry_prots(pmd_pg_vaddr);
                    // all reads

                    if (pud_entry_prots == 0)
                    {
                        *((u64 *)pud_entry_addr) = (*((u64 *)pud_entry_addr)) & prot_flag;
                        asm volatile("invlpg (%0);" ::"r"(addr) : "memory");
                    }
                    else
                    {
                        if (ref_count == 1)
                        {
                            //  printk("pud_entry rw is made 1\n");
                            *((u64 *)pud_entry_addr) = (*((u64 *)pud_entry_addr)) | 8;
                            asm volatile("invlpg (%0);" ::"r"(addr) : "memory");
                        }
                    }

                    // level 1
                    int pgd_entry_prots = page_entry_prots(pud_pg_vaddr);
                    // all reads

                    if (pgd_entry_prots == 0)
                    {
                        *((u64 *)pgd_entry_addr) = (*((u64 *)pgd_entry_addr)) & prot_flag;
                        asm volatile("invlpg (%0);" ::"r"(addr) : "memory");
                    }
                    else
                    {
                        if (ref_count == 1)
                        {
                            //   printk("pgd_entry rw is made 1\n");
                            *((u64 *)pgd_entry_addr) = (*((u64 *)pgd_entry_addr)) | 8;
                            asm volatile("invlpg (%0);" ::"r"(addr) : "memory");
                        }
                    }
                }
            }
        }
    }
}

// function to modify protection of pfns inside a vm_area
void modify_prot_from_vma(struct exec_context *current, u64 start_addr, u64 end_addr, int access_flags)
{
    int num_pages = (end_addr - start_addr) / PAGE_SIZE;
    for (int i = 0; i < num_pages; i++)
    {
        modify_prot_pfn(current, start_addr + i * PAGE_SIZE, access_flags);
    }
}

/**
 * mprotect System call Implementation.
 */
long vm_area_mprotect(struct exec_context *current, u64 addr, int length, int prot)
{
    struct vm_area *protmap_start = NULL;
    struct vm_area *protmap_end = NULL;
    struct vm_area *vm_temp = current->vm_area;
    int num_pages = nearest_page_num(length);
    unsigned long actual_sz = (unsigned long)num_pages * PAGE_SIZE;
    unsigned long end_addr = addr + actual_sz - 1;
    // finding that within which vm_area addr lies
    int is_start_found = 0, is_end_found = 0;
    while (is_start_found == 0 || is_end_found == 0)
    {
        if (is_start_found == 0 && addr >= vm_temp->vm_start && addr < vm_temp->vm_end)
        {
            protmap_start = vm_temp;
            is_start_found = 1;
        }
        else if (is_start_found == 0 && addr >= vm_temp->vm_end && (vm_temp->vm_next == NULL || (addr < vm_temp->vm_next->vm_start)))
        {
            protmap_start = vm_temp;
            is_start_found = 1;
        }

        if (is_end_found == 0 && end_addr >= vm_temp->vm_start && end_addr < vm_temp->vm_end)
        {
            //   printk("protmap_end assigned 1 %x\n", vm_temp);
            protmap_end = vm_temp;
            is_end_found = 1;
        }
        else if (is_end_found == 0 && end_addr >= vm_temp->vm_end && (vm_temp->vm_next == NULL || (end_addr < vm_temp->vm_next->vm_start)))
        {
            //   printk("protmap_end assigned 2 %x\n", vm_temp);
            protmap_end = vm_temp;
            is_end_found = 1;
        }
        vm_temp = vm_temp->vm_next;
    }
    //  printk("code coming here\n");
    //  u64 print_addr = protmap_end->vm_end;
    //  printk("end addr: %x, protmap_end: %x\n", end_addr, print_addr);

    // nothing to change prot of
    if (protmap_start == protmap_end && addr >= protmap_start->vm_end)
    {
        return 0;
    }

    if (addr >= protmap_start->vm_end)
    {
        protmap_start = protmap_start->vm_next;
        addr = protmap_start->vm_start;
    }

    if (end_addr >= protmap_end->vm_end)
    {
        end_addr = protmap_end->vm_end - 1;
    }
    //   printk("code coming here\n");
    //  print_addr = protmap_end->vm_end;
    // printk("end addr: %x, protmap_end: %x\n", end_addr, print_addr);

    if (protmap_start != protmap_end)
    {
        if (prot != protmap_start->access_flags)
        {
            if (addr > protmap_start->vm_start)
            {
                struct vm_area *vm_new = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                vm_new->vm_start = addr;
                vm_new->vm_end = protmap_start->vm_end;
                vm_new->vm_next = protmap_start->vm_next;
                vm_new->access_flags = prot;
                modify_prot_from_vma(current, addr, protmap_start->vm_end, prot);
                stats->num_vm_area++;
                protmap_start->vm_next = vm_new;
                protmap_start->vm_end = addr;
                protmap_start = vm_new;
            }

            // addr == protmap_start->vm_start
            else
            {
                vm_temp = current->vm_area;
                while (vm_temp->vm_next != protmap_start)
                {
                    vm_temp = vm_temp->vm_next;
                }
                // we may have to coalesce is with the prv one
                protmap_start->access_flags = prot;
                if (prot == vm_temp->access_flags && protmap_start->vm_start == vm_temp->vm_end)
                {
                    vm_temp->vm_end = protmap_start->vm_end;
                    vm_temp->vm_next = protmap_start->vm_next;
                    struct vm_area *to_free = protmap_start;
                    protmap_start = vm_temp;
                    os_free((void *)to_free, sizeof(struct vm_area));
                    stats->num_vm_area--;
                }
                modify_prot_from_vma(current, addr, protmap_start->vm_end, prot);
            }
        }

        struct vm_area *vm_temp_curr = protmap_start->vm_next;
        struct vm_area *vm_temp_prev = protmap_start;
        while (vm_temp_curr != protmap_end)
        {
            vm_temp_curr->access_flags = prot;
            if (prot == vm_temp_prev->access_flags && vm_temp_curr->vm_start == vm_temp_prev->vm_end)
            {
                struct vm_area *to_free = vm_temp_curr;
                vm_temp_prev->vm_end = vm_temp_curr->vm_end;
                vm_temp_curr = vm_temp_curr->vm_next;
                vm_temp_prev->vm_next = vm_temp_curr;
                os_free((void *)to_free, sizeof(struct vm_area));
                stats->num_vm_area--;
            }
            else
            {
                vm_temp_curr = vm_temp_curr->vm_next;
                vm_temp_prev = vm_temp_prev->vm_next;
            }
            modify_prot_from_vma(current, vm_temp_curr->vm_start, vm_temp_curr->vm_end, prot);
        }

        if (prot != protmap_end->access_flags)
        {
            // printk("code coming here\n");
            // u64 print_addr = protmap_end->vm_end;
            // printk("end addr: %x, protmap_end: %x\n", end_addr, print_addr);
            if (end_addr < protmap_end->vm_end)
            {
                //   printk("code coming here\n");
                struct vm_area *vm_new = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                vm_new->vm_start = end_addr + 1;
                vm_new->vm_end = protmap_end->vm_end;
                vm_new->access_flags = protmap_end->access_flags;
                vm_new->vm_next = protmap_end->vm_next;
                stats->num_vm_area++;
                protmap_end->vm_end = end_addr + 1;
                protmap_end->vm_next = vm_new;
            }
            protmap_end->access_flags = prot;

            // coalescing protmap_end with the vm_area to its right
            if (protmap_end->vm_next != NULL && protmap_end->vm_end == protmap_end->vm_next->vm_start &&
                protmap_end->access_flags == protmap_end->vm_next->access_flags)
            {
                struct vm_area *to_free = protmap_end->vm_next;
                protmap_end->vm_end = protmap_end->vm_next->vm_end;
                protmap_end->vm_next = protmap_end->vm_next->vm_next;
                os_free((void *)to_free, sizeof(struct vm_area));
                stats->num_vm_area--;
            }
            modify_prot_from_vma(current, protmap_end->vm_start, end_addr + 1, prot);
        }

        // coalescing protmap_end with the vm_area towards its left
        if (prot == vm_temp_prev->access_flags && protmap_end->vm_start == vm_temp_prev->vm_end)
        {
            struct vm_area *to_free = protmap_end;
            vm_temp_prev->vm_end = protmap_end->vm_end;
            vm_temp_prev->vm_next = protmap_end->vm_next;
            os_free((void *)to_free, sizeof(struct vm_area));
            stats->num_vm_area--;
        }
    }
    // protmap_start and protmap_end are the same
    else
    {
        if (addr == protmap_start->vm_start && end_addr == protmap_start->vm_end - 1)
        {
            if (prot != protmap_start->access_flags)
            {
                protmap_start->access_flags = prot;
                // may have to coalsce with the left and right
                struct vm_area *vm_left = current->vm_area;
                struct vm_area *vm_right = protmap_start->vm_next;
                while (vm_left->vm_next != protmap_start)
                {
                    vm_left = vm_left->vm_next;
                }
                // coalescing with the left
                if (vm_left->access_flags == protmap_start->access_flags)
                {
                    struct vm_area *to_free = protmap_start;
                    vm_left->vm_end = protmap_start->vm_end;
                    vm_left->vm_next = protmap_start->vm_next;
                    os_free((void *)to_free, sizeof(struct vm_area));
                    protmap_start = vm_left;
                    stats->num_vm_area--;
                }

                // coalescing with the right
                if (vm_right != NULL && vm_right->access_flags == protmap_start->access_flags)
                {
                    struct vm_area *to_free = vm_right;
                    protmap_start->vm_end = vm_right->vm_end;
                    protmap_start->vm_next = vm_right->vm_next;
                    os_free((void *)to_free, sizeof(struct vm_area));
                    stats->num_vm_area--;
                }

                modify_prot_from_vma(current, addr, end_addr + 1, prot);
            }
        }

        else if (addr == protmap_start->vm_start && end_addr < protmap_start->vm_end - 1)
        {
            if (prot != protmap_start->access_flags)
            {
                struct vm_area *vm_new = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                vm_new->vm_start = end_addr + 1;
                vm_new->vm_end = protmap_start->vm_end;
                vm_new->access_flags = protmap_start->access_flags;
                vm_new->vm_next = protmap_start->vm_next;
                protmap_start->vm_end = end_addr + 1;
                protmap_start->access_flags = prot;
                protmap_start->vm_next = vm_new;
                stats->num_vm_area++;

                // may have to coalesce protmap_start with the left
                struct vm_area *vm_left = current->vm_area;
                while (vm_left->vm_next != protmap_start)
                {
                    vm_left = vm_left->vm_next;
                }
                // coalescing with the left
                if (vm_left->access_flags == protmap_start->access_flags)
                {
                    struct vm_area *to_free = protmap_start;
                    vm_left->vm_end = protmap_start->vm_end;
                    vm_left->vm_next = protmap_start->vm_next;
                    os_free((void *)to_free, sizeof(struct vm_area));
                    protmap_start = vm_left;
                    stats->num_vm_area--;
                }

                modify_prot_from_vma(current, addr, end_addr + 1, prot);
            }
        }

        else if (addr > protmap_start->vm_start && end_addr == protmap_start->vm_end - 1)
        {
            if (prot != protmap_start->access_flags)
            {
                struct vm_area *vm_new = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                vm_new->vm_start = addr;
                vm_new->vm_end = protmap_start->vm_end;
                vm_new->access_flags = prot;
                vm_new->vm_next = protmap_start->vm_next;
                protmap_start->vm_end = addr;
                protmap_start->vm_next = vm_new;
                stats->num_vm_area++;

                // may have to coalesce on the right
                struct vm_area *vm_right = vm_new->vm_next;
                if (vm_right != NULL && vm_right->access_flags == vm_new->access_flags)
                {
                    struct vm_area *to_free = vm_right;
                    vm_new->vm_end = vm_right->vm_end;
                    vm_new->vm_next = vm_right->vm_next;
                    os_free((void *)to_free, sizeof(struct vm_area));
                    stats->num_vm_area--;
                }

                modify_prot_from_vma(current, addr, protmap_start->vm_end, prot);
            }
        }

        else
        {
            if (prot != protmap_start->access_flags)
            {
                struct vm_area *vm_new1 = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                struct vm_area *vm_new2 = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                vm_new1->vm_start = addr;
                vm_new1->vm_end = end_addr + 1;
                vm_new1->vm_next = vm_new2;
                vm_new1->access_flags = prot;
                vm_new2->vm_start = end_addr + 1;
                vm_new2->vm_end = protmap_start->vm_end;
                vm_new2->access_flags = protmap_start->access_flags;
                vm_new2->vm_next = protmap_start->vm_next;
                protmap_start->vm_end = addr;
                protmap_start->vm_next = vm_new1;
                stats->num_vm_area = stats->num_vm_area + 2;
                modify_prot_from_vma(current, addr, end_addr + 1, prot);
            }
        }
    }
    return 0;
}

/**
 * mmap system call implementation.
 */
long vm_area_map(struct exec_context *current, u64 addr, int length, int prot, int flags)
{
    struct vm_area *vm_head = current->vm_area;

    // allocates the dummy node
    if (vm_head == NULL)
    {
        vm_head = (struct vm_area *)os_alloc(sizeof(struct vm_area));
        vm_head->vm_start = MMAP_AREA_START;
        vm_head->vm_end = (vm_head->vm_start) + PAGE_SIZE;
        vm_head->vm_next = NULL;
        vm_head->access_flags = 0x0;
        current->vm_area = vm_head;
        stats->num_vm_area++;
    }

    struct vm_area *vm_temp = vm_head;
    int vm_allocated = 0;
    int num_pages = nearest_page_num(length);
    unsigned long actual_sz = (unsigned long)num_pages * PAGE_SIZE;

    // case when addr is NULL
    if (addr == 0)
    {
        while (vm_allocated == 0)
        {
            if (vm_temp->vm_next == NULL)
            {
                long ret_addr = new_vm_at_end(addr, vm_temp, prot, actual_sz);
                vm_allocated = 1;
                return ret_addr;
            }
            else
            {
                long vm_gap = vm_temp->vm_next->vm_start - vm_temp->vm_end;
                if (vm_gap >= actual_sz)
                {
                    long ret_addr = new_vm_in_between(addr, vm_temp, prot, actual_sz);
                    vm_allocated = 1;
                    return ret_addr;
                }
                // this vm_gap is not sufficient to accomodate this vm_area
                else
                {
                    vm_temp = vm_temp->vm_next;
                }
            }
        }
    }

    // case when addr is not NULL
    else
    {
        int is_addr_psbl = 0;
        while (vm_temp->vm_end < addr && (vm_temp->vm_next != NULL) && (vm_temp->vm_next->vm_start <= addr))
        {
            // printk("code coming here\n");
            vm_temp = vm_temp->vm_next;
        }

        if (vm_temp->vm_end <= addr &&
            ((vm_temp->vm_next == NULL) || (vm_temp->vm_next->vm_start >= addr + actual_sz)))
        {
            is_addr_psbl = 1;
        }

        if (is_addr_psbl == 0 && flags == MAP_FIXED)
        {
            return -1;
        }

        // if the addr is possible
        if (is_addr_psbl)
        {
            //  printk("addrs is possible\n");
            //  printk("addr: %x, vm_tempaddr: %x\n", addr, vm_temp->vm_start);
            if (vm_temp->vm_next == NULL)
            {
                long ret_addr = new_vm_at_end(addr, vm_temp, prot, actual_sz);
                vm_allocated = 1;
                return ret_addr;
            }
            else
            {
                long ret_addr = new_vm_in_between(addr, vm_temp, prot, actual_sz);
                vm_allocated = 1;
                return ret_addr;
            }
        }

        else
        {
            //   printk("code coming here\n");
            vm_temp = vm_head;
            while (vm_allocated == 0)
            {
                if (vm_temp->vm_next == NULL)
                {
                    long ret_addr = new_vm_at_end(0, vm_temp, prot, actual_sz);
                    vm_allocated = 1;
                    return ret_addr;
                }
                else
                {
                    long vm_gap = vm_temp->vm_next->vm_start - vm_temp->vm_end;
                    if (vm_gap >= actual_sz)
                    {
                        long ret_addr = new_vm_in_between(0, vm_temp, prot, actual_sz);
                        vm_allocated = 1;
                        return ret_addr;
                    }
                    // this vm_gap is not sufficient to accomodate this vm_area
                    else
                    {
                        vm_temp = vm_temp->vm_next;
                    }
                }
            }
        }
    }
    return -EINVAL;
}

/**
 * munmap system call implemenations
 */

long vm_area_unmap(struct exec_context *current, u64 addr, int length)
{
    struct vm_area *unmap_start = NULL;
    struct vm_area *unmap_end = NULL;
    struct vm_area *vm_temp = current->vm_area;
    int num_pages = nearest_page_num(length);                       // no. of pages to unmap
    unsigned long actual_sz = (unsigned long)num_pages * PAGE_SIZE; // no. of bytes to unmap
    unsigned long end_addr = addr + actual_sz - 1;                  // end_addr to unmap
    // finding that within which vm_area addr lies
    int is_start_found = 0, is_end_found = 0;
    while (is_start_found == 0 || is_end_found == 0)
    {
        if (is_start_found == 0 && addr >= vm_temp->vm_start && addr < vm_temp->vm_end)
        {
            unmap_start = vm_temp;
            is_start_found = 1;
        }
        else if (is_start_found == 0 && addr >= vm_temp->vm_end && (vm_temp->vm_next == NULL || (addr < vm_temp->vm_next->vm_start)))
        {
            unmap_start = vm_temp;
            is_start_found = 1;
        }

        if (is_end_found == 0 && end_addr >= vm_temp->vm_start && end_addr < vm_temp->vm_end)
        {
            unmap_end = vm_temp;
            is_end_found = 1;
        }
        else if (is_end_found == 0 && end_addr >= vm_temp->vm_end && (vm_temp->vm_next == NULL || (end_addr < vm_temp->vm_next->vm_start)))
        {
            unmap_end = vm_temp;
            is_end_found = 1;
        }
        vm_temp = vm_temp->vm_next;
    }

    // nothing to unmap
    if (unmap_start == unmap_end && addr >= unmap_start->vm_end)
    {
        return 0;
    }

    if (addr >= unmap_start->vm_end)
    {
        unmap_start = unmap_start->vm_next;
        addr = unmap_start->vm_start;
    }

    if (end_addr >= unmap_end->vm_end)
    {
        end_addr = unmap_end->vm_end - 1;
    }

    if (unmap_start != unmap_end)
    {
        vm_temp = unmap_start->vm_next;
        unmap_start->vm_next = unmap_end;
        while (vm_temp != unmap_end)
        {
            struct vm_area *to_free = vm_temp;
            vm_temp = vm_temp->vm_next;
            free_pfn_from_vma(current, to_free->vm_start, to_free->vm_end);
            os_free((void *)to_free, sizeof(struct vm_area));
            stats->num_vm_area--;
        }

        // free unmap_end ->end_addr is == the end of unmap_end
        if (unmap_end->vm_end - 1 == end_addr)
        {
            struct vm_area *to_free = unmap_end;
            unmap_start->vm_next = unmap_end->vm_next;
            free_pfn_from_vma(current, to_free->vm_start, to_free->vm_end);
            os_free((void *)to_free, sizeof(struct vm_area));
            stats->num_vm_area--;
        }
        // end_addr is less than the end_addr of unmap_end
        else
        {
            free_pfn_from_vma(current, unmap_end->vm_start, end_addr + 1);
            unmap_end->vm_start = end_addr + 1;
        }

        // free unmap_start -> addr is = the start address of unmap_start
        if (unmap_start->vm_start == addr)
        {
            vm_temp = current->vm_area;
            while (vm_temp->vm_next != unmap_start)
            {
                vm_temp = vm_temp->vm_next;
            }
            struct vm_area *to_free = unmap_start;
            vm_temp->vm_next = unmap_start->vm_next;
            free_pfn_from_vma(current, to_free->vm_start, to_free->vm_end);
            os_free((void *)to_free, sizeof(struct vm_area));
            stats->num_vm_area--;
        }
        else
        {
            free_pfn_from_vma(current, unmap_start->vm_start, addr);
            unmap_start->vm_end = addr;
        }
    }
    else
    {
        // a hole will be created
        if (addr > unmap_start->vm_start && end_addr < unmap_start->vm_end - 1)
        {

            struct vm_area *vm_new = (struct vm_area *)os_alloc(sizeof(struct vm_area));
            vm_new->vm_start = end_addr + 1;
            vm_new->vm_end = unmap_start->vm_end;
            vm_new->access_flags = unmap_start->access_flags;
            vm_new->vm_next = unmap_start->vm_next;
            unmap_start->vm_end = addr;
            unmap_start->vm_next = vm_new;
            stats->num_vm_area++;
            free_pfn_from_vma(current, addr, end_addr + 1);
        }
        else if (addr > unmap_start->vm_start)
        {
            unmap_start->vm_end = addr;
            free_pfn_from_vma(current, addr, end_addr + 1);
        }
        else if (end_addr < unmap_start->vm_end - 1)
        {
            unmap_end->vm_start = end_addr + 1;
            free_pfn_from_vma(current, addr, end_addr + 1);
        }
        else
        {
            vm_temp = current->vm_area;
            while (vm_temp->vm_next != unmap_start)
            {
                vm_temp = vm_temp->vm_next;
            }
            struct vm_area *to_free = unmap_start;
            vm_temp->vm_next = unmap_start->vm_next;
            os_free((void *)to_free, sizeof(struct vm_area));
            free_pfn_from_vma(current, addr, end_addr + 1);
            stats->num_vm_area--;
        }
    }
    return 0;
}

/**
 * Function will invoked whenever there is page fault for an address in the vm area region
 * created using mmap
 */

long vm_area_pagefault(struct exec_context *current, u64 addr, int error_code)
{
    //  printk("entering pagefault\n");
    //  printk("addr: %x\n", addr);
    struct vm_area *vm_temp = current->vm_area;
    int is_addr_found = 0;
    while (vm_temp->vm_next != NULL && vm_temp->vm_next->vm_start <= addr)
    {
        vm_temp = vm_temp->vm_next;
    }
    if (vm_temp != NULL && addr >= vm_temp->vm_start && addr < vm_temp->vm_end)
    {
        is_addr_found = 1;
    }
    //  printk("line 775 fine\n");
    if (is_addr_found == 0)
    {
        return -1;
    }
    //  printk("line 780 fine\n");
    int vma_access = vm_temp->access_flags;
    int fault_access = ((error_code >> 1) & 1); // = 1 implies access is write
    if (error_code == 4 || error_code == 6)
    {
        // no pfn is allocated
        if (vma_access == PROT_READ && fault_access == 1)
        {
            return -1;
        }
        //    printk("in line 791\n");
        u64 pgdb = (u64)current->pgd; // virtual address of pgd level of page table
        u64 pgdb_v = (u64)osmap(pgdb);
        u64 level_1_bits = ((addr >> 39) & LEVEL_BITS);
        u64 level_2_bits = ((addr >> 30) & LEVEL_BITS);
        u64 level_3_bits = ((addr >> 21) & LEVEL_BITS);
        u64 level_4_bits = ((addr >> 12) & LEVEL_BITS);
        u64 offset = (addr & OFFSET_BITS);

        // printk("addr: %x\n", addr);
        // printk("level 1 bits: %x\n", level_1_bits);
        // printk("level 2 bits: %x\n", level_2_bits);
        // printk("level 3 bits: %x\n", level_3_bits);
        // printk("level 4 bits: %x\n", level_4_bits);
        // printk("Offset: %x\n", offset);

        // level 1 -> pgd
        u64 pgd_entry_addr = pgdb_v + (u64)(level_1_bits * PTE_SIZE);
        u64 pgd_entry = *((u64 *)pgd_entry_addr);
        //   printk("PGD Entry\n: %x", pgd_entry); // debug stat
        int present_bit1 = (pgd_entry & 1);
        u64 shifter = 1;
        if (present_bit1 == 0)
        {
            //   printk("code changing pud entry\n");
            u64 pud_new_pg = os_pfn_alloc(OS_PT_REG);
            //   printk("pud_new_pg: %x\n", pud_new_pg);
            *((u64 *)pgd_entry_addr) = (*((u64 *)pgd_entry_addr)) | shifter;
            *((u64 *)pgd_entry_addr) = (*((u64 *)pgd_entry_addr)) | (fault_access << 3);
            *((u64 *)pgd_entry_addr) = (*((u64 *)pgd_entry_addr)) | (shifter << 4);
            *((u64 *)pgd_entry_addr) = (*((u64 *)pgd_entry_addr)) | (pud_new_pg << 12);
            //  printk("page 1 done\n");
        }
        // structuring the PTE entries depending on access flags
        *((u64 *)pgd_entry_addr) = (*((u64 *)pgd_entry_addr)) | (fault_access << 3);
        pgd_entry = *((u64 *)pgd_entry_addr); // debug stat
        // printk("Modified PGD Entry\n: %x", pgd_entry); // debug stat
        u64 pud_pg_addr = ((u64)(*((u64 *)pgd_entry_addr)) >> 12);
        //  printk("pud_new_pd: %x\n", pud_pg_addr);
        //  printk("level 1 done\n");
        // level 2 -> pud
        u64 pud_pg_vaddr = (u64)(osmap(pud_pg_addr));
        u64 pud_entry_addr = pud_pg_vaddr + (u64)(level_2_bits * PTE_SIZE);
        u64 pud_entry = *((u64 *)pud_entry_addr);
        int present_bit2 = (pud_entry & 1);
        if (present_bit2 == 0)
        {
            u64 pmd_new_pg = os_pfn_alloc(OS_PT_REG);
            *((u64 *)pud_entry_addr) = (*((u64 *)pud_entry_addr)) | shifter;
            *((u64 *)pud_entry_addr) = (*((u64 *)pud_entry_addr)) | (fault_access << 3);
            *((u64 *)pud_entry_addr) = (*((u64 *)pud_entry_addr)) | (shifter << 4);
            *((u64 *)pud_entry_addr) = (*((u64 *)pud_entry_addr)) | (pmd_new_pg << 12);
            //   printk("page 2 done\n");
        }
        // structuring the PTE entries depending on access flags
        *((u64 *)pud_entry_addr) = (*((u64 *)pud_entry_addr)) | (fault_access << 3);
        u64 pmd_pg_addr = ((u64)(*((u64 *)pud_entry_addr)) >> 12);

        //  printk("level 2 done\n");
        // level 3 -> pmd
        u64 pmd_pg_vaddr = (u64)(osmap(pmd_pg_addr));
        u64 pmd_entry_addr = pmd_pg_vaddr + (u64)(level_3_bits * PTE_SIZE);
        u64 pmd_entry = *((u64 *)pmd_entry_addr);
        int present_bit3 = (pmd_entry & 1);
        if (present_bit3 == 0)
        {
            u64 pte_new_pg = os_pfn_alloc(OS_PT_REG);
            *((u64 *)pmd_entry_addr) = (*((u64 *)pmd_entry_addr)) | shifter;
            *((u64 *)pmd_entry_addr) = (*((u64 *)pmd_entry_addr)) | (fault_access << 3);
            *((u64 *)pmd_entry_addr) = (*((u64 *)pmd_entry_addr)) | (shifter << 4);
            *((u64 *)pmd_entry_addr) = (*((u64 *)pmd_entry_addr)) | (pte_new_pg << 12);
            //    printk("page 3 done\n");
        }
        // structuring the PTE entries depending on access flags
        *((u64 *)pmd_entry_addr) = (*((u64 *)pmd_entry_addr)) | (fault_access << 3);
        u64 pte_pg_addr = ((u64)(*((u64 *)pmd_entry_addr)) >> 12);

        //    printk("level 3 done\n");
        // level 4 -> pte
        u64 pte_pg_vaddr = (u64)(osmap(pte_pg_addr));
        u64 pte_entry_addr = pte_pg_vaddr + (u64)(level_4_bits * PTE_SIZE);
        u64 pte_entry = *((u64 *)pte_entry_addr);
        int present_bit4 = (pte_entry & 1);
        if (present_bit4 == 0)
        {
            u64 new_pg = os_pfn_alloc(USER_REG);
            *((u64 *)pte_entry_addr) = (*((u64 *)pte_entry_addr)) | shifter;
            *((u64 *)pte_entry_addr) = (*((u64 *)pte_entry_addr)) | (fault_access << 3);
            *((u64 *)pte_entry_addr) = (*((u64 *)pte_entry_addr)) | (shifter << 4); // re-check
            *((u64 *)pte_entry_addr) = (*((u64 *)pte_entry_addr)) | (new_pg << 12);
            //   printk("page 4 done\n");
        }
        // structuring the PTE entries depending on access flags
        *((u64 *)pte_entry_addr) = (*((u64 *)pte_entry_addr)) | (fault_access << 3);
        //   printk("level 4 done\n");
        asm volatile("invlpg (%0);" ::"r"(addr) : "memory");
    }
    else if (error_code == 0x7)
    {
        return handle_cow_fault(current, addr, vma_access);
    }
    return 1;
}

/**
 * cfork system call implemenations
 * The parent returns the pid of child process. The return path of
 * the child process is handled separately through the calls at the
 * end of this function (e.g., setup_child_context etc.)
 */

// this function copies the page table corresponding to the entries needed to locate addr
int CopyPTE(struct exec_context *ctx, struct exec_context *new_ctx, u64 addr)
{
    //  printk("addr: %x\n", addr);
    //  printk("code entering copy PTE\n");
    //  printk("child pgdb in cpoyPTE: %x\n", new_ctx->pgd);
    u64 level_1_bits = ((addr >> 39) & LEVEL_BITS);
    u64 level_2_bits = ((addr >> 30) & LEVEL_BITS);
    u64 level_3_bits = ((addr >> 21) & LEVEL_BITS);
    u64 level_4_bits = ((addr >> 12) & LEVEL_BITS);

    u64 pgdb = (u64)ctx->pgd;
    u64 pgdb_v = (u64)osmap(pgdb);

    u64 child_pgdb = (u64)new_ctx->pgd;
    u64 child_pgdb_v = (u64)osmap(child_pgdb);

    // level 1 -> pgd
    u64 pgd_entry_addr = pgdb_v + (u64)(level_1_bits * PTE_SIZE);
    u64 pgd_entry = *((u64 *)pgd_entry_addr);

    // make parent rw entry as 0
    *((u64 *)pgd_entry_addr) = *((u64 *)pgd_entry_addr) & 0xFFFFFFFFFFFFFFF7;
    u64 child_pgd_entry_addr = child_pgdb_v + (u64)(level_1_bits * PTE_SIZE);
    u64 child_pgd_entry = *((u64 *)child_pgd_entry_addr);

    int present_bit1 = (pgd_entry & 1);
    int child_present_bit1 = (child_pgd_entry & 1);
    if (present_bit1 == 0)
    {
        //  printk("2\n");
        asm volatile("invlpg (%0);" ::"r"(addr) : "memory");
        return 0;
    }
    else
    {
        if (child_present_bit1 == 0)
        {
            //  printk("3\n");
            // corresponding to this pgd entry in child, we have to allocate a page table
            u64 new_pg = (u64)os_pfn_alloc(OS_PT_REG);
            //  printk("new_pg: %x\n", new_pg);
            u64 new_pg_v = (u64)osmap(new_pg);
            u64 new_pg_temp = new_pg << 12;
            //  printk("new_pg_temp %x\n", new_pg_temp);
            *((u64 *)child_pgd_entry_addr) = (new_pg_temp | 0x11);
            //  printk("child_pgd_entry: %x\n", *((u64 *)child_pgd_entry_addr));
        }

        child_pgd_entry = *((u64 *)child_pgd_entry_addr);
        u64 pud_pg_addr = ((u64)(*((u64 *)pgd_entry_addr)) >> 12);
        u64 child_pud_pg_addr = ((u64)(*((u64 *)child_pgd_entry_addr)) >> 12);
        //  printk("child_pug_pg_addr: %x\n", child_pud_pg_addr);

        //****level 2*********//
        u64 pud_pg_addr_v = (u64)osmap(pud_pg_addr);
        u64 child_pud_pg_addr_v = (u64)osmap(child_pud_pg_addr);
        u64 pud_entry_addr = pud_pg_addr_v + (u64)(level_2_bits * PTE_SIZE);
        u64 pud_entry = *((u64 *)pud_entry_addr);
        //  printk("4.1\n");
        // make parent rw access as 0
        (*((u64 *)pud_entry_addr)) = (*((u64 *)pud_entry_addr)) & 0xFFFFFFFFFFFFFFF7;
        //  printk("4.1.1\n");
        u64 child_pud_entry_addr = child_pud_pg_addr_v + (u64)(level_2_bits * PTE_SIZE);
        //   printk("4.1.2\n");
        u64 child_pud_entry = *((u64 *)child_pud_entry_addr);
        //   printk("4.2\n");
        int present_bit2 = (pud_entry & 1);
        int child_present_bit2 = (child_pud_entry & 1);
        //   printk("4.3\n");
        if (present_bit2 == 0)
        {
            //   printk("5\n");
            asm volatile("invlpg (%0);" ::"r"(addr) : "memory");
            return 0;
        }
        else
        {
            //   printk("6\n");
            if (child_present_bit2 == 0)
            {
                // corresponding to this pgd entry in child, we have to allocate a page table
                u64 new_pg = os_pfn_alloc(OS_PT_REG);
                u64 new_pg_v = (u64)osmap(new_pg);
                *((u64 *)child_pud_entry_addr) = (new_pg << 12) | 0x11;
            }
            child_pud_entry = *((u64 *)child_pud_entry_addr);
            u64 pmd_pg_addr = ((u64)(*((u64 *)pud_entry_addr)) >> 12);
            u64 child_pmd_pg_addr = ((u64)(*((u64 *)child_pud_entry_addr)) >> 12);

            //********level 3*********//
            u64 pmd_pg_addr_v = (u64)osmap(pmd_pg_addr);
            u64 child_pmd_pg_addr_v = (u64)osmap(child_pmd_pg_addr);
            u64 pmd_entry_addr = pmd_pg_addr_v + (u64)(level_3_bits * PTE_SIZE);
            u64 pmd_entry = *((u64 *)pmd_entry_addr);

            // make parent rw access as 0
            *((u64 *)pmd_entry_addr) = *((u64 *)pmd_entry_addr) & 0xFFFFFFFFFFFFFFF7;
            u64 child_pmd_entry_addr = child_pmd_pg_addr_v + (u64)(level_3_bits * PTE_SIZE);
            u64 child_pmd_entry = *((u64 *)child_pmd_entry_addr);

            int present_bit3 = (pmd_entry & 1);
            int child_present_bit3 = (child_pmd_entry & 1);

            if (present_bit3 == 0)
            {
                //    printk("7\n");
                asm volatile("invlpg (%0);" ::"r"(addr) : "memory");
                return 0;
            }
            else
            {
                //    printk("8\n");
                if (child_present_bit3 == 0)
                {
                    // corresponding to this pgd entry in child, we have to allocate a page table
                    u64 new_pg = os_pfn_alloc(OS_PT_REG);
                    u64 new_pg_v = (u64)osmap(new_pg);
                    *((u64 *)child_pmd_entry_addr) = (new_pg << 12) | 0x11;
                }
                child_pmd_entry = *((u64 *)child_pmd_entry_addr);
                u64 pte_pg_addr = ((u64)(*((u64 *)pmd_entry_addr)) >> 12);
                u64 child_pte_pg_addr = ((u64)(*((u64 *)child_pmd_entry_addr)) >> 12);

                //********level 4*************4//
                u64 pte_pg_addr_v = (u64)osmap(pte_pg_addr);
                u64 child_pte_pg_addr_v = (u64)osmap(child_pte_pg_addr);
                u64 pte_entry_addr = pte_pg_addr_v + (u64)(level_4_bits * PTE_SIZE);
                u64 pte_entry = *((u64 *)pte_entry_addr);

                int present_bit4 = (pte_entry & 1);
                if (present_bit4 == 0)
                {
                    //    printk("9\n");
                    asm volatile("invlpg (%0);" ::"r"(addr) : "memory");
                    return 0;
                }
                //  printk("10\n");
                u64 user_pg = (pte_entry >> 12);
                // make parent rw access as 0
                *((u64 *)pte_entry_addr) = *((u64 *)pte_entry_addr) & 0xFFFFFFFFFFFFFFF7;
                u64 child_pte_entry_addr = child_pte_pg_addr_v + (u64)(level_4_bits * PTE_SIZE);
                *((u64 *)child_pte_entry_addr) = *((u64 *)pte_entry_addr);
                get_pfn(user_pg);
            }
        }
    }
    asm volatile("invlpg (%0);" ::"r"(addr) : "memory");
    return 1;
}

long do_cfork()
{
    u32 pid;
    struct exec_context *new_ctx = get_new_ctx();
    struct exec_context *ctx = get_current_ctx();
    /* Do not modify above lines
     *
     * */
    /*--------------------- Your code [start]---------------*/
    new_ctx->ppid = ctx->pid;
    new_ctx->type = ctx->type;
    new_ctx->state = ctx->state;
    new_ctx->regs = ctx->regs;
    new_ctx->pgd = os_pfn_alloc(OS_PT_REG);
    //  printk("new_ctx->ip: %x\n", new_ctx->regs.entry_rip);
    //  printk("ctx->ip: %x\n", ctx->regs.entry_rip);
    //    printk("child pgdb in cfork: %x\n", new_ctx->pgd);
    for (int i = 0; i < MAX_MM_SEGS; i++)
    {
        new_ctx->mms[i] = ctx->mms[i];
    }
    //    printk("new_pid: %x\n", new_ctx->pid);
    //   printk("ppid: %x\n", new_ctx->ppid);

    struct vm_area *vm_head = (struct vm_area *)os_alloc(sizeof(struct vm_area));
    vm_head->vm_start = MMAP_AREA_START;
    vm_head->vm_end = MMAP_AREA_START + PAGE_SIZE;
    vm_head->access_flags = 0x0;
    vm_head->vm_next = NULL;
    new_ctx->vm_area = vm_head;
    new_ctx->used_mem = ctx->used_mem;
    struct vm_area *par_vma = ctx->vm_area->vm_next;
    struct vm_area *child_vma = vm_head;

    while (par_vma != NULL)
    {
        struct vm_area *new_vm = (struct vm_area *)os_alloc(sizeof(struct vm_area));
        new_vm->vm_start = par_vma->vm_start;
        new_vm->vm_end = par_vma->vm_end;
        new_vm->access_flags = par_vma->access_flags;
        new_vm->vm_next = NULL;
        child_vma->vm_next = new_vm;
        par_vma = par_vma->vm_next;
        child_vma = child_vma->vm_next;
    }

    for (int i = 0; i < MAX_OPEN_FILES; i++)
    {
        new_ctx->files[i] = ctx->files[i];
    }

    // printk("Basic copying is done\n");
    for (int i = 0; i < MAX_MM_SEGS; i++)
    {

        u64 page_virtual_addr = new_ctx->mms[i].start;
        //    printk("MM_seg_start %x, MM_seg_start %x\n ", new_ctx->mms[i].start, new_ctx->mms[i].next_free);
        if (i < 3)
        {
            while (page_virtual_addr < new_ctx->mms[i].next_free)
            {
                //   printk("start address: %x\n", page_virtual_addr);
                int ret_val = CopyPTE(ctx, new_ctx, page_virtual_addr);
                if (ret_val == 0)
                {
                    break;
                }
                page_virtual_addr = page_virtual_addr + PAGE_SIZE;
            }
        }

        else
        {
            page_virtual_addr = new_ctx->mms[i].end;
            //    printk("MM_seg_start %x, MM_seg_start %x\n ", new_ctx->mms[i].start, new_ctx->mms[i].end);
            while (page_virtual_addr < new_ctx->mms[i].end)
            {
                //  printk("start address: %x\n", page_virtual_addr);
                int ret_val = CopyPTE(ctx, new_ctx, page_virtual_addr);
                if (ret_val == 0)
                {
                    break;
                }
                page_virtual_addr = page_virtual_addr + PAGE_SIZE;
            }
        }
    }
    //   printk("mm_seg works fine\n");
    struct vm_area *curr = new_ctx->vm_area->vm_next;
    while (curr != NULL)
    {
        u64 page_virtual_addr = curr->vm_start;
        while (page_virtual_addr < curr->vm_end)
        {
            int ret_val = CopyPTE(ctx, new_ctx, page_virtual_addr);
            page_virtual_addr = page_virtual_addr + PAGE_SIZE;
        }
        curr = curr->vm_next;
    }
    //   printk("vm area works fine\n");
    pid = new_ctx->pid;

    /*--------------------- Your code [end] ----------------*/

    /*
     * The remaining part must not be changed
     */
    copy_os_pts(ctx->pgd, new_ctx->pgd);
    do_file_fork(new_ctx);
    setup_child_context(new_ctx);
    return pid;
}

/* Cow fault handling, for the entire user address space
 * For address belonging to memory segments (i.e., stack, data)
 * it is called when there is a CoW violation in these areas.
 *
 * For vm areas, your fault handler 'vm_area_pagefault'
 * should invoke this function
 * */

long handle_cow_fault(struct exec_context *current, u64 vaddr, int access_flags)
{
    if (access_flags == PROT_READ)
    {
        return -1;
    }
    u64 pgdb = (u64)current->pgd;
    u64 pgdb_v = (u64)osmap(pgdb);
    u64 level_1_bits = ((vaddr >> 39) & LEVEL_BITS);
    u64 level_2_bits = ((vaddr >> 30) & LEVEL_BITS);
    u64 level_3_bits = ((vaddr >> 21) & LEVEL_BITS);
    u64 level_4_bits = ((vaddr >> 12) & LEVEL_BITS);
    u64 offset = (vaddr & OFFSET_BITS);
    u64 pgd_entry_addr = pgdb_v + (u64)(level_1_bits * PTE_SIZE);
    u64 pgd_entry = *((u64 *)pgd_entry_addr);
    int present_bit1 = (pgd_entry & 1);

    if (present_bit1 == 1)
    {
        u64 pud_pg_addr = ((u64)(*((u64 *)pgd_entry_addr)) >> 12);
        u64 pud_pg_vaddr = (u64)(osmap(pud_pg_addr));
        u64 pud_entry_addr = pud_pg_vaddr + (u64)(level_2_bits * PTE_SIZE);
        u64 pud_entry = *((u64 *)pud_entry_addr);
        int present_bit2 = (pud_entry & 1);

        if (present_bit2 == 1)
        {
            u64 pmd_pg_addr = ((u64)(*((u64 *)pud_entry_addr)) >> 12);
            u64 pmd_pg_vaddr = (u64)(osmap(pmd_pg_addr));
            u64 pmd_entry_addr = pmd_pg_vaddr + (u64)(level_3_bits * PTE_SIZE);
            u64 pmd_entry = *((u64 *)pmd_entry_addr);
            int present_bit3 = (pmd_entry & 1);

            if (present_bit3 == 1)
            {
                u64 pte_pg_addr = ((u64)(*((u64 *)pmd_entry_addr)) >> 12);
                u64 pte_pg_vaddr = (u64)(osmap(pte_pg_addr));
                u64 pte_entry_addr = pte_pg_vaddr + (u64)(level_4_bits * PTE_SIZE);
                u64 pte_entry = *((u64 *)pte_entry_addr);
                int present_bit4 = (pte_entry & 1);
                //   printk("pte entry before: %x\n", pte_entry);
                if (present_bit4 == 1)
                {
                    u64 user_pg_addr = ((u64)(*((u64 *)pte_entry_addr)) >> 12);
                    u64 user_pg_vaddr = (u64)(osmap(user_pg_addr));
                    u64 new_pg = (u64)os_pfn_alloc(USER_REG);
                    u64 new_pg_va = (u64)(osmap(new_pg));
                    memcpy((char *)new_pg_va, (char *)user_pg_vaddr, PAGE_SIZE);
                    u64 last_12_bytes = (*((u64 *)pte_entry_addr)) & 0xFFF;
                    *((u64 *)pte_entry_addr) = (new_pg << 12) | last_12_bytes;

                    // giving the write access at each level
                    *((u64 *)pte_entry_addr) = (*((u64 *)pte_entry_addr)) | 8;
                    *((u64 *)pmd_entry_addr) = (*((u64 *)pmd_entry_addr)) | 8;
                    *((u64 *)pud_entry_addr) = (*((u64 *)pud_entry_addr)) | 8;
                    *((u64 *)pgd_entry_addr) = (*((u64 *)pgd_entry_addr)) | 8;

                    put_pfn((u32)user_pg_addr);
                    // deleting the previous user page if its refcount becomes zero
                    if (get_pfn_refcount((u32)user_pg_addr) == 0)
                    {
                        os_pfn_free(USER_REG, user_pg_addr);
                    }
                    asm volatile("invlpg (%0);" ::"r"(vaddr) : "memory");
                }
            }
        }
    }

    return 1;
}
