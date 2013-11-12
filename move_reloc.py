from __future__ import print_function

import glob
import pickle
import os

import elftools.construct

from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_RELOC_TYPE_x64

int64 = elftools.construct.SNInt64("value")

class Statistics(object):
    def __init__(self):
        self.missing_symbols = set()

    def event(self, name):
        if name not in self.__dict__: self.__dict__[name] = 0
        self.__dict__[name] += 1

    def print(self):
        for name, val in self.__dict__.items():
            try:
                print("%20s: %d" % (name, val))
            except TypeError: pass

stats = Statistics()

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
        if rela_text is None: return # no relocations
        rela_text_offset = rela_text.header.sh_offset
        text_offset = ef.get_section_by_name('.text').header.sh_offset

        for i, reloc in enumerate(rela_text.iter_relocations()):
            stats.event('relocations_present')
            # only support absolute x64 relocations
            if not reloc.entry.r_info_type == ENUM_RELOC_TYPE_x64['R_X86_64_64']:
                stats.event('relocations_wrong_type')
                continue

            # get symbol name (while supporting section symbols)
            sym = symtab.get_symbol(reloc.entry.r_info_sym)
            if sym.entry.st_info.type == 'STT_SECTION':
                name = ef.get_section(sym.entry.st_shndx).name
            else:
                name = symtab.get_symbol(reloc.entry.r_info_sym).name

            if name not in symbol_map:
                stats.event('relocations_no_prefloc')
                stats.missing_symbols.add(name)
                continue

            assert reloc.is_RELA()
            address = symbol_map[name]
            offset = text_offset + reloc.entry.r_offset
            a_offset = rela_text_offset + i*ef.structs.Elf_Rela.sizeof() + addend_offset
            patches.append(Patch(offset, a_offset, address))
            stats.event('relocations_changed')

    with open(file_name, 'r+b') as fp:
        for p in patches:
            p.patch_stream(fp)


def get_symbol_locations(elf_file, text_location):
    result = dict()
    symtab = elf_file.get_section_by_name('.symtab')
    text_shndx = min(i for (i, x) in enumerate(elf_file.iter_sections()) if x.name == '.text')

    if symtab is not None:
        for symbol in symtab.iter_symbols():
            # only process symbols for the .text section
            if symbol.entry.st_shndx == text_shndx and len(symbol.name) > 0:
                result[symbol.name] = text_location + symbol.entry.st_value

    return result


def scan_directory(path, start_location=0x4003e0):
    """
    Reads all object files in a given directory and assigns a preferred location
    for each object's .text section. Returns a symbol map containing a
    preferred locations for each symbol defined in all these objects.
    """
    location = dict()
    symbol_map = dict() # maps symbol name to its preferred location
    current = 0

    print('Determining object locations...', end='')
    for file_name in glob.glob(path + "/*.o"):
        with open(file_name, 'rb') as fp:
            elf_file = ELFFile(fp)
            location[file_name] = current
            # TODO: support alignment, objects without .text sections etc.
            current += elf_file.get_section_by_name('.text').header.sh_size
    print('DONE')

    print('Calculating the symbol map...', end='')
    for (file_name, location) in location.items():
        # add a "section" symbol for each object .text section
        symbol_map[os.path.basename(file_name) + '#.text'] = location
        with open(file_name, 'rb') as fp:
            elf_file = ELFFile(fp)
            symbol_map.update(get_symbol_locations(elf_file, location))
    print('DONE')

    with open(path + '/.symbol_map', 'w') as fp:
        pickle.dump(symbol_map, fp)

    return symbol_map


def process_directory(path):
    try:
        with open(path + '/.symbol_map', 'r') as fp:
            symbol_map = pickle.load(fp)
            print('Loaded precomputed symbol map.')
    except IOError:
        symbol_map = scan_directory(path)

    for file_name in glob.glob(path + "/*.o"):
        symbol_map['.text'] = symbol_map[os.path.basename(file_name) + '#.text']
        set_preffered(file_name, symbol_map)

    stats.print()
