#include <context.h>
#include <memory.h>
#include <lib.h>
#include <entry.h>
#include <file.h>
#include <tracer.h>

///////////////////////////////////////////////////////////////////////////
//// 		Start of Trace buffer functionality 		      /////
///////////////////////////////////////////////////////////////////////////

int is_valid_mem_range(unsigned long buff, u32 count, int access_bit)
{

    struct exec_context *current_process = get_current_ctx();
    struct mm_segment *mm_seg_ptr = current_process->mms;
    struct vm_area *vm_area_ptr = current_process->vm_area;
    unsigned long buff_addr = (unsigned long)buff;

    // checking in the mm_segment array
    int valid_addr_found = 0;
    int access = 0;
    for (int i = 0; i < MAX_MM_SEGS; i++)
    {
        if (buff_addr >= mm_seg_ptr[i].start && buff_addr + count - 1 <= mm_seg_ptr[i].end - 1)
        {
            valid_addr_found = 1;
            access = mm_seg_ptr[i].access_flags;
            break;
        }
    }

    if (valid_addr_found == 0)
    {
        // check whether this address is in vm_area
        while (vm_area_ptr != NULL)
        {
            if (vm_area_ptr->vm_start <= buff_addr && vm_area_ptr->vm_end - 1 >= buff_addr + count - 1)
            {
                valid_addr_found = 1;
                access = vm_area_ptr->access_flags;
                break;
            }
            vm_area_ptr = vm_area_ptr->vm_next;
        }
    }

    // if the buff is not in a valid address
    if (valid_addr_found == 0)
    {
        return -1;
    }

    if (access_bit & access)
    {
        return 1;
    }
    return 0;
}

long trace_buffer_close(struct file *filep)
{
    if (filep == NULL)
    {
        return -EINVAL;
    }
    struct trace_buffer_info *trace_buffer_ptr = filep->trace_buffer;
    char *temp_trace_mem_addr = trace_buffer_ptr->trace_mem_addr;
    // printk("Freeing page address %x\n", temp_trace_mem_addr);

    os_page_free(USER_REG, (void *)temp_trace_mem_addr); // freeing trace buffer memory
    trace_buffer_ptr->trace_mem_addr = NULL;
    filep->trace_buffer = NULL;

    os_free(trace_buffer_ptr, sizeof(struct trace_buffer_info)); // freeing trace_buffer_info
    struct fileops *file_fn_ptr = filep->fops;
    filep->fops = NULL;

    os_free(file_fn_ptr, sizeof(struct fileops)); // freeing struct fileops
    struct file *temp_filep = filep;
    filep = NULL;

    os_free((void *)temp_filep, sizeof(struct file)); // finally freeing the file
    return 0;
}

int trace_buffer_read(struct file *filep, char *buff, u32 count)
{
    if (count < 0)
    {
        return -EINVAL;
    }
    if (buff == NULL)
    {
        return -EINVAL;
    }
    u32 mode = filep->mode;

    if (mode != O_READ && mode != O_RDWR)
    {
        return -EINVAL;
    }

    struct trace_buffer_info *trace_buffer_ptr = filep->trace_buffer;
    char *trace_buff_addr = trace_buffer_ptr->trace_mem_addr;
    int read_offset = trace_buffer_ptr->read_offset;
    int write_offset = trace_buffer_ptr->write_offset;
    int is_full = trace_buffer_ptr->is_full;
    int is_empty = trace_buffer_ptr->is_empty;

    // checking buffer validity
    unsigned long buff_addr = (unsigned long)buff;
    int is_write_buf_access = is_valid_mem_range(buff_addr, count, 2);
    // if the buff is not in a valid address or doesnt have write access

    if (is_write_buf_access == -1 || is_write_buf_access == 0)
    {
        return -EBADMEM;
    }

    if (is_empty)
    {
        return 0; // return 0 of there is nothing to read
    }

    // adjusting read count if there are not enough bytes written in trace buffer
    if (read_offset >= write_offset && (read_offset + count >= TRACE_BUFFER_MAX_SIZE) &&
        ((read_offset + count) % TRACE_BUFFER_MAX_SIZE) >= write_offset)
    {
        count = TRACE_BUFFER_MAX_SIZE - read_offset + write_offset;
        trace_buffer_ptr->is_empty = 1; // buffer is empty
    }
    else if (read_offset < write_offset && (read_offset + count) >= write_offset)
    {
        count = write_offset - read_offset;
        trace_buffer_ptr->is_empty = 1; // buffer is empty
    }

    for (int i = 0; i < count; i++)
    {
        buff[i] = *(trace_buff_addr + ((read_offset + i) % TRACE_BUFFER_MAX_SIZE));
    }
    trace_buffer_ptr->read_offset = (read_offset + count) % TRACE_BUFFER_MAX_SIZE;

    if (is_full && count > 0)
    {
        trace_buffer_ptr->is_full = 0;
    }
    return count;
}

int trace_buffer_write(struct file *filep, char *buff, u32 count)
{

    if (count < 0)
    {
        return -EINVAL;
    }
    if (buff == NULL)
    {
        return -EINVAL;
    }
    u32 mode = filep->mode;
    if (mode != O_WRITE && mode != O_RDWR)
    {
        return -EINVAL;
    }

    struct trace_buffer_info *trace_buffer_ptr = filep->trace_buffer;
    char *trace_buff_addr = trace_buffer_ptr->trace_mem_addr;
    int read_offset = trace_buffer_ptr->read_offset;
    int write_offset = trace_buffer_ptr->write_offset;
    int is_full = trace_buffer_ptr->is_full;
    int is_empty = trace_buffer_ptr->is_empty;

    // checking the validity of buff
    unsigned long buff_addr = (unsigned long)buff;
    int is_read_buf_access = is_valid_mem_range(buff_addr, count, 1);
    // if the buff is not in a valid address or buff doesnt have read access
    if (is_read_buf_access == -1 || is_read_buf_access == 0)
    {
        return -EBADMEM;
    }

    if (is_full)
    {
        return 0; // return 0 if the buffer is full
    }

    // adjusting write count if count is more than the space left
    if (write_offset >= read_offset && (write_offset + count >= TRACE_BUFFER_MAX_SIZE) &&
        ((write_offset + count) % TRACE_BUFFER_MAX_SIZE) >= read_offset)
    {
        count = TRACE_BUFFER_MAX_SIZE - write_offset + read_offset;
        trace_buffer_ptr->is_full = 1; // buffer is full
    }
    else if (write_offset < read_offset && (write_offset + count) >= read_offset)
    {
        count = read_offset - write_offset;
        trace_buffer_ptr->is_full = 1; // buffer is full
    }

    for (int i = 0; i < count; i++)
    {
        *(trace_buff_addr + ((write_offset + i) % TRACE_BUFFER_MAX_SIZE)) = buff[i];
    }
    trace_buffer_ptr->write_offset = (write_offset + count) % TRACE_BUFFER_MAX_SIZE;
    if (is_empty && count > 0)
    {
        // something is written in the buffer so buffer cant be empty
        trace_buffer_ptr->is_empty = 0;
    }
    return count;
}

int sys_create_trace_buffer(struct exec_context *current, int mode)
{
    if (mode != O_READ && mode != O_WRITE && mode != O_RDWR)
    {
        return -EINVAL;
    }
    struct file **fphead = current->files;
    struct file *temp_fp = fphead[0];
    int ct_fp = 0;

    // finding lowest free file descriptor
    while (ct_fp < MAX_OPEN_FILES && temp_fp != NULL)
    {
        if (fphead[ct_fp] == NULL)
        {
            temp_fp = NULL;
            break;
        }
        ct_fp++;
    }
    if (ct_fp == MAX_OPEN_FILES)
    {
        return -EINVAL;
    }

    fphead[ct_fp] = (struct file *)os_alloc(sizeof(struct file));
    if (fphead[ct_fp] == NULL)
    {
        return -ENOMEM;
    }
    fphead[ct_fp]->type = TRACE_BUFFER;
    fphead[ct_fp]->mode = mode;
    fphead[ct_fp]->offp = 0;
    fphead[ct_fp]->ref_count = 1;
    fphead[ct_fp]->inode = NULL;

    struct trace_buffer_info *trace_buffer_ptr =
        (struct trace_buffer_info *)os_alloc(sizeof(struct trace_buffer_info));

    if (trace_buffer_ptr == NULL)
    {
        return -ENOMEM;
    }
    trace_buffer_ptr->trace_mem_addr = (char *)os_page_alloc(USER_REG);
    //	printk("Allocated OS page %x\n", trace_buffer_ptr->trace_mem_addr);
    if (trace_buffer_ptr->trace_mem_addr == NULL)
    {
        return -ENOMEM;
    }

    trace_buffer_ptr->read_offset = 0;
    trace_buffer_ptr->write_offset = 0;
    trace_buffer_ptr->is_full = 0;
    trace_buffer_ptr->is_empty = 1;
    fphead[ct_fp]->trace_buffer = trace_buffer_ptr;

    struct fileops *file_fn_ptr = (struct fileops *)os_alloc(sizeof(struct fileops));
    if (file_fn_ptr == NULL)
    {
        return -ENOMEM;
    }

    file_fn_ptr->read = trace_buffer_read;
    file_fn_ptr->write = trace_buffer_write;
    file_fn_ptr->close = trace_buffer_close;
    fphead[ct_fp]->fops = file_fn_ptr;
    return ct_fp;
}

///////////////////////////////////////////////////////////////////////////
//// 		Start of strace functionality 		      	      /////
///////////////////////////////////////////////////////////////////////////

// function to assign number of arguments to different syscalls
// num_args[i] represents the no. of arguments in a syscall corresponding to
// syscall number i
void give_syscall_arg_num(int *num_args)
{
    for (int i = 0; i <= 61; i++)
    {
        num_args[i] = 0;
    }
    num_args[1] = 1;
    num_args[2] = 0;
    num_args[4] = 2;
    num_args[7] = 1;
    num_args[8] = 2;
    num_args[9] = 2;
    num_args[10] = 0;
    num_args[11] = 0;
    num_args[12] = 1;
    num_args[14] = 1;
    num_args[15] = 0;
    num_args[16] = 4;
    num_args[17] = 2;
    num_args[18] = 3;
    num_args[19] = 1;
    num_args[20] = 0;
    num_args[21] = 0;
    num_args[22] = 0;
    num_args[23] = 2;
    num_args[24] = 3;
    num_args[25] = 3;
    num_args[27] = 1;
    num_args[28] = 2;
    num_args[29] = 1;
    num_args[30] = 3;
    num_args[35] = 4;
    num_args[36] = 1;
    num_args[37] = 2;
    num_args[38] = 0;
    num_args[39] = 3;
    num_args[40] = 2;
    num_args[41] = 3;
}

// This function is used to write into the trace buffer from another function in the OS
int write_trace_from_os(u64 syscall_num, u64 param1, u64 param2, u64 param3, u64 param4,
                        u64 num_of_args, struct trace_buffer_info *trace_buffer)
{
    char *trace_mem_addr = trace_buffer->trace_mem_addr;
    int write_offset = trace_buffer->write_offset;
    char *trace_adj_addr = trace_mem_addr + (write_offset % TRACE_BUFFER_MAX_SIZE);
    u64 *ull_ptr = (u64 *)trace_adj_addr;
    *(ull_ptr) = syscall_num;
    trace_buffer->write_offset = (write_offset + sizeof(u64)) % TRACE_BUFFER_MAX_SIZE;
    u64 args_arr[4];
    args_arr[0] = param1;
    args_arr[1] = param2;
    args_arr[2] = param3;
    args_arr[3] = param4;
    for (int i = 0; i < num_of_args; i++)
    {
        write_offset = trace_buffer->write_offset;
        trace_adj_addr = trace_mem_addr + (write_offset % TRACE_BUFFER_MAX_SIZE);
        u64 *ull_ptr2 = (u64 *)trace_adj_addr;
        *(ull_ptr2) = args_arr[i];
        trace_buffer->write_offset = (write_offset + sizeof(u64)) % TRACE_BUFFER_MAX_SIZE;
    }
    char ch_delimiter = ' ';
    write_offset = trace_buffer->write_offset;
    trace_adj_addr = trace_mem_addr + (write_offset % TRACE_BUFFER_MAX_SIZE);
    *(trace_adj_addr) = ch_delimiter;
    trace_buffer->write_offset = (write_offset + sizeof(char)) % TRACE_BUFFER_MAX_SIZE;
    if (trace_buffer->is_empty)
    {
        trace_buffer->is_empty = 0;
    }
    return 0;
}

int perform_tracing(u64 syscall_num, u64 param1, u64 param2, u64 param3, u64 param4)
{
    int num_args[62];
    give_syscall_arg_num(num_args);
    struct exec_context *current = get_current_ctx();
    struct strace_head *st_md_base = current->st_md_base;

    // tracing should be performed when the process is not forked and
    // sytem call is not start or end strace and tracing must be enabled
    if (syscall_num != 37 && st_md_base != NULL && st_md_base->is_traced != 0 && syscall_num != 38)
    {
        int strace_fd = st_md_base->strace_fd;
        int tracing_mode = st_md_base->tracing_mode;
        struct file **fphead = current->files;
        struct file *trace_file_fp = fphead[strace_fd];
        struct trace_buffer_info *trace_buffer = trace_file_fp->trace_buffer;
        if (tracing_mode == FULL_TRACING)
        {
            st_md_base->count++;
            write_trace_from_os(syscall_num, param1, param2, param3, param4, num_args[syscall_num], trace_buffer);
        }
        else if (tracing_mode == FILTERED_TRACING)
        {
            int is_syscall_there = 0;
            struct strace_info *st_info = st_md_base->next;
            while (st_info != NULL)
            {
                if (st_info->syscall_num == syscall_num)
                {
                    is_syscall_there = 1;
                    break;
                }
                st_info = st_info->next;
            }
            if (is_syscall_there)
            {
                st_md_base->count++;
                write_trace_from_os(syscall_num, param1, param2, param3, param4, num_args[syscall_num], trace_buffer);
            }
        }
    }
    return 0;
}

int sys_strace(struct exec_context *current, int syscall_num, int action)
{
    struct strace_head *st_md_base = current->st_md_base; // can be null
    if (st_md_base == NULL)
    {
        st_md_base = (struct strace_head *)os_alloc(sizeof(struct strace_head));
        if (st_md_base == NULL)
        {
            return -EINVAL;
        }
        st_md_base->count = 0;
        st_md_base->is_traced = 0;
        st_md_base->tracing_mode = FILTERED_TRACING;
        st_md_base->strace_fd = -1; // no trace buffer is assigned yet
        st_md_base->next = NULL;
        st_md_base->last = NULL;
        current->st_md_base = st_md_base;
    }
    int is_fd_present = 0;
    int sys_ct = 0;
    // checking if fd already there in the list
    struct strace_info *st_info = st_md_base->next;
    while (st_info != NULL)
    {
        if (st_info->syscall_num == syscall_num)
        {
            is_fd_present = 1;
        }
        sys_ct++;
        st_info = st_info->next;
    }

    if (action == ADD_STRACE)
    {
        if (is_fd_present)
        {
            return -EINVAL;
        }
        if (sys_ct == STRACE_MAX)
        {
            return -EINVAL;
        }
        st_info = st_md_base->next;
        if (st_info == NULL)
        {
            struct strace_info *curr_st_info = (struct strace_info *)os_alloc(sizeof(struct strace_info));
            if (curr_st_info == NULL)
            {
                return -EINVAL;
            }
            curr_st_info->next = NULL;
            curr_st_info->syscall_num = syscall_num;
            st_md_base->next = curr_st_info;
            st_md_base->last = curr_st_info;
        }
        else
        {
            struct strace_info *curr_st_info = (struct strace_info *)os_alloc(sizeof(struct strace_info));
            if (curr_st_info == NULL)
            {
                return -EINVAL;
            }
            curr_st_info->next = NULL;
            curr_st_info->syscall_num = syscall_num;
            st_md_base->last->next = curr_st_info;
            st_md_base->last = curr_st_info;
        }
    }
    else if (action == REMOVE_STRACE)
    {
        if (!is_fd_present)
        {
            return -EINVAL;
        }
        st_info = st_md_base->next;
        if (st_info->syscall_num == syscall_num)
        {
            st_md_base->next = st_info->next;
            if (st_info->next == NULL)
            {
                st_md_base->last = NULL;
            }
            os_free(st_info, sizeof(st_info));
        }
        else
        {
            while (st_info->next->syscall_num != syscall_num)
            {
                st_info = st_info->next;
            }
            struct strace_info *st_to_free = st_info->next;
            st_info->next = st_info->next->next;
            if (st_to_free->next == NULL)
            {
                st_md_base->last = st_info;
            }
            os_free(st_to_free, sizeof(struct strace_info));
        }
    }
    return 0;
}

int sys_read_strace(struct file *filep, char *buff, u64 count)
{
    struct trace_buffer_info *trace_buffer = filep->trace_buffer;
    char *trace_mem_addr = trace_buffer->trace_mem_addr;
    int read_offset = trace_buffer->read_offset;
    int write_offset = trace_buffer->write_offset;
    int is_empty = trace_buffer->is_empty;
    if (is_empty)
    {
        return 0;
    }
    char *trace_adj_addr = trace_mem_addr + (read_offset % TRACE_BUFFER_MAX_SIZE);
    int read_ct = 0;
    int char_ct = 0;
    while (read_offset != write_offset && read_ct <= count)
    {
        while (*(trace_adj_addr) != ' ')
        {
            for (int i = 0; i < sizeof(u64); i++)
            {
                buff[char_ct] = *(trace_mem_addr + ((read_offset + i) % TRACE_BUFFER_MAX_SIZE));
                char_ct++;
            }
            trace_buffer->read_offset = (trace_buffer->read_offset + sizeof(u64)) % TRACE_BUFFER_MAX_SIZE;
            read_offset = trace_buffer->read_offset;
            trace_adj_addr = trace_mem_addr + (read_offset % TRACE_BUFFER_MAX_SIZE);
        }
        if (*(trace_adj_addr) == ' ')
        {
            trace_buffer->read_offset = (trace_buffer->read_offset + sizeof(char)) % TRACE_BUFFER_MAX_SIZE;
            read_offset = trace_buffer->read_offset;
            trace_adj_addr = trace_mem_addr + (read_offset % TRACE_BUFFER_MAX_SIZE);
        }
        read_ct++;
    }
    if (read_offset == write_offset)
    {
        trace_buffer->is_empty = 1;
    }
    return char_ct;
}

int sys_start_strace(struct exec_context *current, int fd, int tracing_mode)
{

    struct strace_head *st_md_base = current->st_md_base;
    if (st_md_base == NULL)
    {
        st_md_base = (struct strace_head *)os_alloc(sizeof(struct strace_head));
        if (st_md_base == NULL)
        {
            return -EINVAL;
        }
        st_md_base->next = NULL;
        st_md_base->last = NULL;
    }
    st_md_base->count = 0;
    st_md_base->is_traced = 1;
    st_md_base->tracing_mode = tracing_mode;
    st_md_base->strace_fd = fd;
    current->st_md_base = st_md_base;
    return 0;
}

int sys_end_strace(struct exec_context *current)
{
    struct strace_head *st_md_base = current->st_md_base;
    struct strace_info *st_info = st_md_base->next;
    st_md_base->next = NULL;
    st_md_base->last = NULL;
    if (st_info != NULL)
    {
        while (st_info->next != NULL)
        {
            struct strace_info *st_to_free = st_info;
            st_info = st_info->next;
            os_free(st_to_free, sizeof(struct strace_info));
        }
        struct strace_info *st_to_free = st_info;
        st_info = NULL;
        os_free(st_to_free, sizeof(struct strace_info));
    }
    current->st_md_base = NULL;
    os_free(st_md_base, sizeof(struct strace_head));
    return 0;
}

///////////////////////////////////////////////////////////////////////////
//// 		Start of ftrace functionality 		      	      /////
///////////////////////////////////////////////////////////////////////////

long do_ftrace(struct exec_context *ctx, unsigned long faddr, long action, long nargs, int fd_trace_buffer)
{
    if (action == ADD_FTRACE)
    {
        if (ctx->ft_md_base == NULL)
        {
            struct ftrace_head *ft_md_base = (struct ftrace_head *)os_alloc(sizeof(struct ftrace_head));
            if (ft_md_base == NULL)
            {
                return -EINVAL;
            }
            ft_md_base->count = 0;
            ft_md_base->next = NULL;
            ft_md_base->last = NULL;
            ctx->ft_md_base = ft_md_base;
        }
        struct ftrace_head *ft_md_base = ctx->ft_md_base;
        struct ftrace_info *temp_info = ft_md_base->next;
        int is_already_there = 0;
        int fn_count = 0;
        while (temp_info != NULL)
        {
            if (temp_info->faddr == faddr)
            {
                is_already_there = 1;
            }
            fn_count++;
            temp_info = temp_info->next;
        }
        if (is_already_there)
        {
            return -EINVAL;
        }
        if (fn_count == FTRACE_MAX)
        {
            return -EINVAL;
        }
        struct ftrace_info *curr_ft_info = (struct ftrace_info *)os_alloc(sizeof(struct ftrace_info));
        if (curr_ft_info == NULL)
        {
            return -EINVAL;
        }
        curr_ft_info->faddr = faddr;
        curr_ft_info->num_args = nargs;
        curr_ft_info->fd = fd_trace_buffer;
        curr_ft_info->capture_backtrace = 0;
        curr_ft_info->next = NULL;
        if (ft_md_base->next == NULL)
        {
            ft_md_base->next = curr_ft_info;
            ft_md_base->last = curr_ft_info;
        }
        else
        {
            ft_md_base->last->next = curr_ft_info;
        }
    }

    else if (action == REMOVE_FTRACE)
    {
        struct ftrace_head *ft_md_base = ctx->ft_md_base;
        if (ft_md_base == NULL)
        {
            return -EINVAL;
        }
        struct ftrace_info *ft_info = ft_md_base->next;
        int is_already_there = 0;
        while (ft_info != NULL)
        {
            if (ft_info->faddr == faddr)
            {
                is_already_there = 1;
                break;
            }
            ft_info = ft_info->next;
        }
        if (!is_already_there)
        {
            return -EINVAL;
        }

        // checking if tracing is enabled for this function
        char *faddr_ptr = (char *)faddr;
        if (*(faddr_ptr) == INV_OPCODE)
        {
            // if tracing is enabled, disabling it first
            long ret_val = do_ftrace(ctx, faddr, DISABLE_FTRACE, nargs, fd_trace_buffer);
            if (ret_val == -EINVAL)
            {
                return -EINVAL;
            }
        }
        ft_info = ft_md_base->next;
        if (ft_info->faddr == faddr)
        {
            ft_md_base->next = ft_info->next;
            if (ft_info->next == NULL)
            {
                ft_md_base->last = NULL;
            }
            os_free(ft_info, sizeof(struct ftrace_info));
        }
        else
        {
            while (ft_info->next->faddr != faddr)
            {
                ft_info = ft_info->next;
            }
            struct ftrace_info *ft_to_free = ft_info->next;
            ft_info->next = ft_info->next->next;
            if (ft_to_free->next == NULL)
            {
                ft_md_base->last = ft_info;
            }
            os_free(ft_to_free, sizeof(struct ftrace_info));
        }
    }

    else if (action == ENABLE_FTRACE || action == ENABLE_BACKTRACE)
    {
        struct ftrace_head *ft_md_base = ctx->ft_md_base;
        if (ft_md_base == NULL)
        {
            return -EINVAL;
        }
        struct ftrace_info *ft_info = ft_md_base->next;
        while (ft_info != NULL)
        {
            if (ft_info->faddr == faddr)
            {
                break;
            }
            ft_info = ft_info->next;
        }
        // function is not added to the list of functions to be traced
        if (ft_info == NULL)
        {
            return -EINVAL;
        }
        // if the action is ENABLE_BACKTRACE
        if (action == ENABLE_BACKTRACE)
        {
            ft_info->capture_backtrace = 1;
        }
        // replacing first four bytes at faddr and saving backup
        char *func_addr = (char *)faddr;

        // if the tracing was already enabled
        if (*(func_addr) == INV_OPCODE)
        {
            return 0;
        }

        ft_info->code_backup[0] = *(func_addr);
        ft_info->code_backup[1] = *(func_addr + 1);
        ft_info->code_backup[2] = *(func_addr + 2);
        ft_info->code_backup[3] = *(func_addr + 3);
        *(func_addr) = INV_OPCODE;
        *(func_addr + 1) = INV_OPCODE;
        *(func_addr + 2) = INV_OPCODE;
        *(func_addr + 3) = INV_OPCODE;
    }

    else if (action == DISABLE_FTRACE || action == DISABLE_BACKTRACE)
    {
        struct ftrace_head *ft_md_base = ctx->ft_md_base;
        if (ft_md_base == NULL)
        {
            return -EINVAL;
        }
        struct ftrace_info *ft_info = ft_md_base->next;
        while (ft_info != NULL)
        {
            if (ft_info->faddr == faddr)
            {
                break;
            }
            ft_info = ft_info->next;
        }
        if (ft_info == NULL)
        {
            return -EINVAL;
        }
        // if the action is DISABLE_BACKTRACE
        if (action == DISABLE_BACKTRACE)
        {
            ft_info->capture_backtrace = 0;
        }
        char *func_addr = (char *)faddr;

        // if the tracing was not enabled
        if (*(func_addr) != INV_OPCODE)
        {
            return 0;
        }

        *(func_addr) = ft_info->code_backup[0];
        *(func_addr + 1) = ft_info->code_backup[1];
        *(func_addr + 2) = ft_info->code_backup[2];
        *(func_addr + 3) = ft_info->code_backup[3];
    }
    else
    {
        return -EINVAL;
    }
    return 0;
}

// function to write in the trace buffer from the os function handle_ftrace_fault
int write_ftrace_from_os(struct ftrace_info *ft_info, u64 faddr, u64 param1, u64 param2, u64 param3, u64 param4, u64 param5,
                         u64 num_of_args, struct trace_buffer_info *trace_buffer)
{
    char *trace_mem_addr = trace_buffer->trace_mem_addr;
    int write_offset = trace_buffer->write_offset;
    char *trace_adj_addr = trace_mem_addr + (write_offset % TRACE_BUFFER_MAX_SIZE);
    u64 *ull_ptr = (u64 *)trace_adj_addr;
    *(ull_ptr) = faddr;
    trace_buffer->write_offset = (write_offset + sizeof(u64)) % TRACE_BUFFER_MAX_SIZE;
    u64 args_arr[5];
    args_arr[0] = param1;
    args_arr[1] = param2;
    args_arr[2] = param3;
    args_arr[3] = param4;
    args_arr[4] = param5;
    for (int i = 0; i < num_of_args; i++)
    {
        write_offset = trace_buffer->write_offset;
        trace_adj_addr = trace_mem_addr + (write_offset % TRACE_BUFFER_MAX_SIZE);
        u64 *ull_ptr2 = (u64 *)trace_adj_addr;
        *(ull_ptr2) = args_arr[i];
        trace_buffer->write_offset = (write_offset + sizeof(u64)) % TRACE_BUFFER_MAX_SIZE;
    }
    if (ft_info->capture_backtrace == 0)
    {
        char ch_delimiter = ' ';
        write_offset = trace_buffer->write_offset;
        trace_adj_addr = trace_mem_addr + (write_offset % TRACE_BUFFER_MAX_SIZE);
        *(trace_adj_addr) = ch_delimiter;
        trace_buffer->write_offset = (write_offset + sizeof(char)) % TRACE_BUFFER_MAX_SIZE;
    }
    if (trace_buffer->is_empty)
    {
        trace_buffer->is_empty = 0;
    }
    return 0;
}

// function to write backtrace info in the trace buffer from the os function handle_ftrace_fault
int write_backtrace_from_os(u64 ret_addrs[], int ret_ct, struct trace_buffer_info *trace_buffer)
{
    char *trace_mem_addr = trace_buffer->trace_mem_addr;
    int write_offset = trace_buffer->write_offset;
    char *trace_adj_addr = trace_mem_addr + (write_offset % TRACE_BUFFER_MAX_SIZE);
    for (int i = 0; i < ret_ct; i++)
    {
        write_offset = trace_buffer->write_offset;
        trace_adj_addr = trace_mem_addr + (write_offset % TRACE_BUFFER_MAX_SIZE);
        u64 *ull_ptr = (u64 *)trace_adj_addr;
        *(ull_ptr) = ret_addrs[i];
        trace_buffer->write_offset = (write_offset + sizeof(u64)) % TRACE_BUFFER_MAX_SIZE;
    }
    char ch_delimiter = ' ';
    write_offset = trace_buffer->write_offset;
    trace_adj_addr = trace_mem_addr + (write_offset % TRACE_BUFFER_MAX_SIZE);
    *(trace_adj_addr) = ch_delimiter;
    trace_buffer->write_offset = (write_offset + sizeof(char)) % TRACE_BUFFER_MAX_SIZE;
    if (trace_buffer->is_empty)
    {
        trace_buffer->is_empty = 0;
    }
    return 0;
}

// Fault handler
long handle_ftrace_fault(struct user_regs *regs)
{
    struct exec_context *ctx = get_current_ctx();
    unsigned long faddr = regs->entry_rip;
    struct ftrace_head *ft_md_base = ctx->ft_md_base;
    if (ft_md_base == NULL)
    {
        return -EINVAL;
    }
    struct ftrace_info *ft_info = ft_md_base->next;

    while (ft_info != NULL)
    {
        if (ft_info->faddr == faddr)
        {
            break;
        }
        ft_info = ft_info->next;
    }
    if (ft_info == NULL)
    {
        return -EINVAL;
    }
    ft_md_base->count = ft_md_base->count + 1;
    int ftrace_fd = ft_info->fd;
    u64 nargs = ft_info->num_args;
    struct file **fphead = ctx->files;
    struct file *trace_fp = fphead[ftrace_fd];
    struct trace_buffer_info *trace_buffer = trace_fp->trace_buffer;
    u64 arg1 = regs->rdi;
    u64 arg2 = regs->rsi;
    u64 arg3 = regs->rdx;
    u64 arg4 = regs->rcx;
    u64 arg5 = regs->r8;
    write_ftrace_from_os(ft_info, faddr, arg1, arg2, arg3, arg4, arg5, nargs, trace_buffer);

    regs->entry_rsp = regs->entry_rsp - 8;
    u64 *stack_ptr = (u64 *)regs->entry_rsp;
    *(stack_ptr) = regs->rbp;
    regs->rbp = regs->entry_rsp;
    regs->entry_rip = regs->entry_rip + 4;

    // handling backtracing
    if (ft_info->capture_backtrace)
    {
        u64 *return_addrs = (u64 *)os_page_alloc(USER_REG);
        return_addrs[0] = ft_info->faddr;
        int ret_ct = 1;
        u64 ret_addr = *((u64 *)(regs->rbp + 8));
        u64 prev_rbp = *((u64 *)(regs->rbp));
        while (ret_addr != END_ADDR)
        {
            return_addrs[ret_ct] = ret_addr;
            ret_addr = *((u64 *)(prev_rbp + 8));
            prev_rbp = *((u64 *)(prev_rbp));
            ret_ct++;
        }

        write_backtrace_from_os(return_addrs, ret_ct, trace_buffer);
        os_page_free(USER_REG, (void *)return_addrs);
    }

    return 0;
}

int sys_read_ftrace(struct file *filep, char *buff, u64 count)
{
    struct trace_buffer_info *trace_buffer = filep->trace_buffer;
    char *trace_mem_addr = trace_buffer->trace_mem_addr;
    int read_offset = trace_buffer->read_offset;
    int write_offset = trace_buffer->write_offset;
    int is_empty = trace_buffer->is_empty;
    if (is_empty)
    {
        return 0;
    }
    char *trace_adj_addr = trace_mem_addr + (read_offset % TRACE_BUFFER_MAX_SIZE);
    int read_ct = 0;
    int char_ct = 0;
    while (read_offset != write_offset && read_ct <= count)
    {
        while (*(trace_adj_addr) != ' ')
        {
            for (int i = 0; i < sizeof(u64); i++)
            {
                buff[char_ct] = *(trace_mem_addr + ((read_offset + i) % TRACE_BUFFER_MAX_SIZE));
                char_ct++;
            }
            trace_buffer->read_offset = (trace_buffer->read_offset + sizeof(u64)) % TRACE_BUFFER_MAX_SIZE;
            read_offset = trace_buffer->read_offset;
            trace_adj_addr = trace_mem_addr + (read_offset % TRACE_BUFFER_MAX_SIZE);
        }
        if (*(trace_adj_addr) == ' ')
        {
            trace_buffer->read_offset = (trace_buffer->read_offset + sizeof(char)) % TRACE_BUFFER_MAX_SIZE;
            read_offset = trace_buffer->read_offset;
            trace_adj_addr = trace_mem_addr + (read_offset % TRACE_BUFFER_MAX_SIZE);
        }
        read_ct++;
    }
    if (read_offset == write_offset)
    {
        trace_buffer->is_empty = 1;
    }
    return char_ct;
}
