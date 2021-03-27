#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

static void syscall_handler (struct intr_frame *);
void sys_exit(int status);
void sys_write(int fd, const void* buffer, unsigned size);
void check_address_validity(const void* vaddr);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	int *p = f->esp;
	check_address_validity(p);

	switch(*p)
	{
		case SYS_EXIT:
		check_address_validity(p+1);
		sys_exit(*(p+1));

		case SYS_WRITE:
		check_address_validity(p+5);
		check_address_validity(p+6);
		check_address_validity(*(p+6));
		check_address_validity(p+7);
		sys_write(*(p+5),(const void *)(*(p+6)), (unsigned)(*(p+7)));
		f->eax = *(p+7);

		//default:
		//printf("System call not implemented yet %d\n", *p);

	}
//  printf ("system call!\n");
//  thread_exit ();
}

///:::
void sys_exit(int status)
{
	thread_current()->exit_status = status;
	printf("%s: exit status = %d\n", thread_current()->name, status);
	thread_exit();
}

///:::
void sys_write(int fd, const void* buffer, unsigned size)
{
	if (fd == 1)
	{
		putbuf(buffer, size);
	}
	else
	{
		printf("Not supposed to print anywhere else for now\n");
	}
}

///:::
void check_address_validity(const void* vaddr)
{
	if (vaddr==NULL || !is_user_vaddr(vaddr))
		sys_exit(-1);
	void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
	if (!ptr) 
		sys_exit(-1);
}