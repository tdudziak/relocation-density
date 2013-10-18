from __future__ import print_function

from elftools.elf.elffile import ELFFile
import numpy as np
import sys

def fragment_sizes(fp):
    ef = ELFFile(fp)
    text_size = ef.get_section_by_name(b'.text').header.sh_size
    rels = ef.get_section_by_name(b'.rela.text')

    if rels is None: # no relocations for .text
        yield text_size
        return

    offsets = [r.entry.r_offset for r in rels.iter_relocations()]
    offsets.sort()

    start = 0
    for offset in offsets:
        if offset-start >= 1:
            yield offset-start
        start = offset+1

    if text_size-1-start >= 1:
        yield text_size-1-start


def file_fragment_sizes(files):
    for fname in files:
        with open(fname, 'rb') as fp:
            for x in fragment_sizes(fp):
                yield x


def main(files):
    frags = np.fromiter(file_fragment_sizes(files), int)
    print('Total number of fragments: %d' % frags.size)
    print('Mean fragment size: %f; median: %d' % (np.mean(frags), np.median(frags)))
    for ex in range(1, 7):
        x = 4**ex
        mask = (frags > x)
        print('#fragments bigger than %5d: %10d (%.2f%%)' % (x, np.sum(mask), 100.0*np.mean(mask)))


if __name__ == '__main__':
    if len(sys.argv) <= 1:
        print("Usage: %s <object files>" % sys.argv[0])
    else:
        main(sys.argv[1:])
