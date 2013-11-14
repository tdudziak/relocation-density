from __future__ import print_function

import os
import re
import pickle

def _parse_file_entry(x):
    m = re.match('([^(]*)(\((.*)\))?$', x.strip())
    if m:
        fname = m.group(1)
        if not os.path.exists(fname.strip()):
            return None

        ident = m.group(3)
        if ident is None:
            ident = os.path.basename(os.path.realpath(fname))

        return ident
    else:
        return None


def _is_file_entry(x):
    m = re.match('([^(]*)(\((.*)\))?$', x.strip())
    if m:
        fname = m.group(1)
        # TODO: check the inside of an archive as well?
        return os.path.exists(fname.strip())
    else:
        return False


def _get_entries(lines):
    xs = []
    for line in lines:
        last = xs
        xs = line.split()

        if len(xs) == 0:
            continue

        ident = _parse_file_entry(xs[-1])
        if ident is None:
            continue

        if xs[0][0] == '.':
            yield xs + [ident]
        elif len(last) > 0 and last[0][0] == '.':
            yield last + xs + [ident]


def _is_string(x):
    try:
        x + ''
        return True
    except TypeError:
        return False


def parse_mapfile(mapfile):
    """
    Creates a symbol_map-like dictionary from a Gold map file.

    An argument `mapfile' can be a string (interpreted as a pathname), an
    opened file stream, or a sequence of strings (interpreted as lines of the
    map file).
    """
    result = dict()
    fp = None

    if _is_string(mapfile):
        lines = fp = open(mapfile)
    elif hasattr(mapfile, '__iter__'):
        # assume mapfile is a collection of lines (stream, list, etc.)
        lines = mapfile
    else:
        raise ValueError()

    try:
        for section, loc, _, path, ident in _get_entries(lines):
            loc = int(loc, base=16)
            if loc != 0:
                result[(ident, section)] = loc

        return result
    finally:
        if fp is not None:
            fp.close()


def mapfile_to_symbol_map(object_dir, mapfile):
    """
    Saves in object_dir a symbol_map.pickle file created from a given Gold
    map file.
    """
    symbol_map = parse_mapfile(mapfile)
    with open(object_dir + '/symbol_map.pickle', 'wb') as fp:
        pickle.dump(symbol_map, fp)
