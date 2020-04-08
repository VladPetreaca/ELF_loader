/*
 * Loader Implementation
 *
 * 2018, Operating Systems
 */

#include <sys/mman.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "exec_parser.h"

static int fd;
static so_exec_t *exec;
static struct sigaction old;
static int pgSize;

static void handler(int sig, siginfo_t *info, void *ucontext)
{
	int i;
	uintptr_t f_addr;
	int *vect;

	/* check if i receive a SIGSEGV signal */
	if (sig != SIGSEGV) {
		old.sa_sigaction(sig, info, ucontext);
		return;
	}

	/* get the fault address */
	f_addr = (uintptr_t)info->si_addr;

	for (i = 0; i < exec->segments_no; i++) {
		uintptr_t end;

		end = exec->segments[i].vaddr + exec->segments[i].mem_size;

		/* check if the fault address is in the specified segment */
		if (f_addr >= exec->segments[i].vaddr && f_addr < end) {
			int index;
			size_t pages_in_seg;

			index = (int)(f_addr - exec->segments[i].vaddr) / pgSize;
			pages_in_seg = exec->segments[i].mem_size / pgSize;

			/* assgin to the data the "mapped" vector */
			if (exec->segments[i].data == NULL) {
				vect = calloc(pages_in_seg, sizeof(int));

				if (vect == NULL) {
					fprintf(stderr, "Error vect\n");
					return;
				}
				exec->segments[i].data = vect;
			}

			/* check if the fault page is mapped */
			if (((int *)(exec->segments[i].data))[index] == 1) {
				old.sa_sigaction(sig, info, ucontext);
				return;
			}

			int len;
			uintptr_t start_addr;
			int size;
			int f_size;

			f_size = (int)(exec->segments[i].file_size);
			start_addr = exec->segments[i].vaddr + index * pgSize;
			size = f_size - index * pgSize;

			/* check if i didn't reach to the eof */
			if (size > pgSize)
				len = pgSize;
			else
				len = size;

			/* mapp the entire page */
			if (len > 0) {
				mmap((void *)start_addr, len
				, exec->segments[i].perm
				, MAP_PRIVATE | MAP_FIXED, fd
				, exec->segments[i].offset + index * pgSize);
			} else {
				mmap((void *)start_addr, pgSize, PROT_WRITE,
				MAP_PRIVATE | MAP_FIXED | MAP_ANON, -1, 0);

				memset((void *)start_addr, 0, pgSize);

				mprotect((void *)start_addr, pgSize,
				exec->segments[i].perm);
			}

			((int *)(exec->segments[i].data))[index] = 1;
			return;
		}
	}

	old.sa_sigaction(sig, info, ucontext);
}

int so_init_loader(void)
{
	/* TODO: initialize on-demand loader */
	struct sigaction sa;
	int check;

	memset(&sa, 0, sizeof(sa));

	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = handler;

	check = sigemptyset(&sa.sa_mask);

	if (check < 0) {
		printf("Error sigemptyset\n");
		return -1;
	}

	check = sigaddset(&sa.sa_mask, SIGSEGV);

	if (check < 0) {
		printf("Eroor sigaddset\n");
		return -1;
	}

	check = sigaction(SIGSEGV, &sa, &old);

	if (check < 0) {
		printf("Error sigaction\n");
		return -1;
	}

	return -1;
}

int so_execute(char *path, char *argv[])
{
	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		printf("Error open fd\n");
		return -1;
	}

	pgSize = getpagesize();

	so_start_exec(exec, argv);

	return -1;
}
