#!/bin/sh

set -e

# check if args are set
if [ "$#" != "1" ]; then
    echo "$0 <file>"
    exit 1
fi

# set vars
filename="$1"
name="$(basename $1 | cut -d '.' -f 1)"

# create workspace
mkdir -p .compile
cd .compile

# generate assembly
python3 ../compile.py "../$filename" > "./$name.as"

# assemble 
nasm -o "$name.o" "$name.as" -f elf
ld -o "$name" "$name.o" -s -m elf_i386
chmod +x "$name"

# print shellcode
objdump -d "./$name" | grep '[0-9a-f]:' | grep -v 'file' | cut -f 2 -d ':' | cut -f 1-6 -d ' ' | tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | sed 's/ /\\x/g' | paste -d '' -s | sed 's/^/"/' | sed 's/$/"/g' | cut -d '"' -f 2
