package main

// #cgo LDFLAGS: -L. -llibrary
// #include "library-bridge.h"
import (
	"C"
	"debug/macho"
	"fmt"
	"log"

	"github.com/bnagy/gapstone"
)

func main() {

	fatFile, err := macho.OpenFat("/Users/blacktop/Downloads/levin/jtool2")
	if err != nil {
		log.Fatal(err)
	}
	for _, arch := range fatFile.Arches {
		fmt.Println(arch.FatArchHeader)
		for _, section := range arch.Sections {
			fmt.Println(section)
		}

		// for _, sym := range arch.Symtab.Syms {
		// 	fmt.Println(sym.Name)
		// }
	}

	kcache, err := macho.Open("kernel")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(kcache.FileHeader)

	engine, err := gapstone.New(
		gapstone.CS_ARCH_X86,
		gapstone.CS_MODE_32,
	)

	if err == nil {

		defer engine.Close()

		maj, min := engine.Version()
		log.Printf("Hello Capstone! Version: %v.%v\n", maj, min)

		var x86Code32 = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34" +
			"\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91" +
			"\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00" +
			"\x8d\x87\x89\x67\x00\x00\xb4\xc6"

		insns, err := engine.Disasm(
			[]byte(x86Code32), // code buffer
			0x10000,           // starting address
			0,                 // insns to disassemble, 0 for all
		)

		if err == nil {
			log.Printf("Disasm:\n")
			for _, insn := range insns {
				log.Printf("0x%x:\t%s\t\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)
			}
			return
		}
		log.Fatalf("Disassembly error: %v", err)
	}
	log.Fatalf("Failed to initialize engine: %v", err)
}
