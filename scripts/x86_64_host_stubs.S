/*
 * Link-only x86_64 libc entry points for the ELF-to-WASM test path.
 *
 * Calls to these symbols are intercepted by the translator before their
 * bodies execute. Keeping tiny definitions here gives the compiler direct,
 * symbol-resolvable call targets without pulling an x86_64 libc into an ARM
 * build host.
 */
.text

.macro host_stub name
    .global \name
    .type \name, @function
\name:
    ret
    .size \name, .-\name
.endm

host_stub printf
host_stub puts
host_stub exit
host_stub malloc
host_stub calloc
host_stub free
host_stub gettimeofday
host_stub clock_gettime
host_stub atoi
host_stub fopen
host_stub scanf
host_stub fprintf
host_stub fclose
host_stub fflush
host_stub fwrite
host_stub open
host_stub fstat
host_stub strerror
host_stub __errno_location
host_stub __isoc99_scanf
host_stub putchar
host_stub pow
host_stub feclearexcept
host_stub fetestexcept
host_stub fesetround
host_stub m_exit
host_stub m_write
host_stub m_strlen
host_stub m_putchar
host_stub printi
host_stub print
host_stub print_arr

.bss
.align 8
.global stdout
stdout:
    .quad 0
.global stderr
stderr:
    .quad 0

.section .note.GNU-stack,"",@progbits
