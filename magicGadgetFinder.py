from elftools.elf.elffile import ELFFile
from pwn import asm, disasm
import argparse

def find_bytecodes_in_elf(file_path, bytecodes):

    with open(file_path, 'rb') as f:
        elf = ELFFile(f)

        for segment in elf.iter_segments():
            if segment['p_type'] == 'PT_LOAD':
                data = segment.data()
                
                for bytecode in bytecodes:
                    index = data.find(bytecode)
                    if index != -1:
                        print('-' * 18)
                        print(f"{hex(segment['p_vaddr'] + index)}:")
                        print(f"{disasm(bytecode)}")
                    

bytecodes = [
    b"\x01\x5D\xC3\x90\xC3", # add DWORD PTR [ebp-0x3d], ebx
    b"H\x8bP8H\x89\xc7\xffR ", # mov rdx, qword ptr [rax + 0x38]; mov rdi, rax; call qword ptr [rdx + 0x20];

]


def main():
    parser = argparse.ArgumentParser(description="Search magic_gadget in ELF file")
    parser.add_argument("file", help="Path to the ELF file")

    args = parser.parse_args()

    find_bytecodes_in_elf(args.file, bytecodes)


if __name__ == "__main__":
    main()