from __future__ import print_function

import glob
import pickle
import os
import sys

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
                print("%20s: %d" % (name, val), file=sys.stderr)
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


# TODO: support section map
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


class ObjectDir(object):
    def __init__(self, path):
        self.path = path
        self.resources = dict()

    def filenames(self):
        return glob.glob(self.path + "/*.o")

    def iter_objects(self):
        for file_name in self.filenames():
            with open(file_name, 'rb') as fp:
                elf_file = ELFFile(fp)
                yield (os.path.basename(file_name), elf_file)

    def get_resource(self, name):
        file_name = self.path + '/' + name + '.pickle'
        result = self.resources.get(name)

        if result is None:
            try:
                sys.stderr.write('Trying to load ' + name + ' from file...')
                sys.stderr.flush()
                with open(file_name, 'rb') as fp:
                    result = pickle.load(fp)
                sys.stderr.write('DONE\n')
            except IOError:
                sys.stderr.write('FAILED\nCreating ' + name + '...')
                sys.stderr.flush()

                if name == 'section_map':
                    result = create_section_map(self)
                elif name == 'symbol_map':
                    result = create_symbol_map(self)
                else:
                    raise ValueError('invalid resource')

                sys.stderr.write('DONE\nSaving ' + name + ' to disk...')
                sys.stderr.flush()
                with open(file_name, 'wb') as fp:
                    pickle.dump(result, fp)
                sys.stderr.write('DONE\n')

        self.resources[name] = result
        return result


def create_section_map(object_dir, start_location=0x4003e0):
    section_map = dict()
    section_start = start_location

    for ident, elf_file in object_dir.iter_objects():
        # TODO: support alignment, page-level permissions etc.
        for section in elf_file.iter_sections():
            # TODO: skip sections that will not be loaded to memory (.comment etc)
            if section.name is not None and len(section.name) > 0:
                section_map[(ident, section.name)] = section_start
                section_start += section.header.sh_size

    return section_map


def create_symbol_map(object_dir):
    symbol_map = dict()
    section_map = object_dir.get_resource('section_map')

    for ident, elf_file in object_dir.iter_objects():
        symtab = elf_file.get_section_by_name('.symtab')
        if symtab is None: continue # no symbols

        for symbol in symtab.iter_symbols():
            if not isinstance(symbol.entry.st_shndx, int):
                continue # no associated section

            section = elf_file.get_section(symbol.entry.st_shndx)
            section_loc = section_map.get((ident, section.name))
            if section_loc is not None:
                symbol_loc = section_loc + symbol.entry.st_value
                symbol_map[symbol.name] = symbol_loc

    return symbol_map


def process_directory(path):
    object_dir = ObjectDir(path)
    # section_map = get_resource(path, 'section_map')
    # symbol_map = get_resource(path, 'symbol_map')

    # for file_name in glob.glob(path + "/*.o"):
        # set_preffered(file_name, symbol_map) # TODO: section locations

    stats.print()
