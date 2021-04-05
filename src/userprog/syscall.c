#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

static void syscall_handler (struct intr_frame *);
void sys_exit(int status);
void sys_write(int fd, const void* buffer, unsigned size);
pid_t sys_exec(const char *cmdline);
int sys_wait(pid_t pid);
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

	//printf("syscall_handler %d\n", *p);
	switch(*p)
	{
		case SYS_EXIT:
		check_address_validity(p+1);
		sys_exit(*(p+1));
		break;

		case SYS_WRITE:
		check_address_validity(p+5);
		check_address_validity(p+6);
		check_address_validity(*(p+6));
		check_address_validity(p+7);
		sys_write(*(p+5),(const void *)(*(p+6)), (unsigned)(*(p+7)));
		f->eax = *(p+7);
		break;

		case SYS_EXEC:
		check_address_validity(p+1);
		check_address_validity(*(p+1));
		f->eax = sys_exec(*(p+1));
		break;

		case SYS_WAIT:
		check_address_validity(p+1);
		f->eax = sys_wait((pid_t) *(p+1));
		break;

		default:
		printf("System call not implemented yet %d\n", *p);

	}
//  printf ("system call!\n");
//  thread_exit ();
}

///:::
void sys_exit(int status)
{
	struct thread * cur = thread_current();
	cur->exit_status = status;
	struct list_elem *elem;
	//printf("sys_exit1 %d\n", cur->parent->tid);
	for (elem = list_begin(&(cur->parent->children)); elem != list_end(&(cur->parent->children)); elem = list_next(elem))
	{
		struct child * ch = list_entry(elem, struct child, child_elem);
		//printf("sys_exit2 %d %d\n", ch->tid, cur->tid);
		if (ch->tid == cur->tid)
		{
	  		ch->exit_status = status;
		}
	}
	printf("%s: exit(%d)\n", thread_current()->name, status);
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
pid_t sys_exec(const char *cmdline)
{
	//printf("sys_exec %s\n", cmdline);
	pid_t pid;
	char *file_name = cmdline;
	lock_acquire(&file_lock);

	char *save_ptr;
	char *extracted_file_name;
	extracted_file_name = (char *) malloc(strlen(file_name)+1);
	strlcpy (extracted_file_name, file_name, strlen(file_name)+1);
	extracted_file_name = strtok_r(extracted_file_name, " ", &save_ptr);
	struct file * f = filesys_open(extracted_file_name);
	if (f == NULL) 
	{
		pid = -1;
		lock_release(&file_lock);
	}
	else 
	{
		file_close(f);
		pid = process_execute(file_name);
		lock_release(&file_lock);
		sema_down(&thread_current()->sema_exec);
	}
	//printf("sys_exec %d\n", thread_current()->tid);
	return pid;
}

///:::
int sys_wait(pid_t pid)
{
	return process_wait(pid);
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