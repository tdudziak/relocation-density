from __future__ import print_function

import elftools.construct

from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_RELOC_TYPE_x64

int64 = elftools.construct.SNInt64("value")

class Patch(object):
    def __init__(self, target_offset, addend_offset, pref_addr):
        self.offsets = [target_offset, addend_offset]
        self.pref_addr = pref_addr

    def patch(self, old_target, old_addend):
        return (self.pref_addr, old_addend - self.pref_addr + old_target)

    def patch_stream(self, fp):
        old = []
        for x in self.offsets:
            fp.seek(x)
            old.append(int64.parse_stream(fp))

        new = self.patch(*old)
        for (i, x) in enumerate(self.offsets):
            fp.seek(x)
            int64.build_stream(new[i], fp)


def set_preffered(file_name, symbol_map):
    patches = []

    with open(file_name, 'rb') as fp:
        ef = ELFFile(fp)
        assert ef.elfclass == 64
        symtab = ef.get_section_by_name('.symtab')

        # calculate r_addend offset inside the Elf_Rela structure
        addend_offset = 0
        for x in ef.structs.Elf_Rela.subcons:
            if x.name == 'r_addend': break
            addend_offset += x.sizeof()

        rela_text = ef.get_section_by_name('.rela.text')
        rela_text_offset = rela_text.header.sh_offset
        text_offset = ef.get_section_by_name('.text').header.sh_offset

        for i, reloc in enumerate(rela_text.iter_relocations()):
            # only support absolute x64 relocations
            if not reloc.entry.r_info_type == ENUM_RELOC_TYPE_x64['R_X86_64_64']:
                continue

            # get symbol name (while supporting section symbols)
            sym = symtab.get_symbol(reloc.entry.r_info_sym)
            if sym.entry.st_info.type == 'STT_SECTION':
                name = ef.get_section(sym.entry.st_shndx).name
            else:
                name = symtab.get_symbol(reloc.entry.r_info_sym).name

            if name not in symbol_map:
                continue

            assert reloc.is_RELA()
            address = symbol_map[name]
            offset = text_offset + reloc.entry.r_offset
            a_offset = rela_text_offset + i*ef.structs.Elf_Rela.sizeof() + addend_offset
            patches.append(Patch(offset, a_offset, address))

    with open(file_name, 'r+b') as fp:
        for p in patches:
            p.patch_stream(fp)
