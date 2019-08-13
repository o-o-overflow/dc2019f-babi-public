#!/usr/bin/python
import sys

target = '/babi' if len(sys.argv) < 2 else sys.argv[1]
origin = '/babi.orig' if len(sys.argv) < 3 else sys.argv[2]

MAXIMAL_CHANGES = 200

BLACKLIST = [
        'main',
        'signal_handler',
        ]

class InvalidPatch(Exception):
    pass

try:
    a = open(target).read()
    b = open(origin).read()

    # check file size
    if len(a) != len(b):
        raise InvalidPatch('size mismatch (%d != %d)' % (len(a), len(b)))

    # record diffs
    diff = []
    for i in xrange(len(a)):
        if a[i] != b[i]:
            diff.append(i)
            if len(diff) > MAXIMAL_CHANGES:
                raise InvalidPatch('too many changes (differences > %d)' %
                        MAXIMAL_CHANGES)

    # TODO lock down ranges

    # now it's safe to load with pwnlib
    from pwn import elf

    try:
        e = elf.ELF(origin)
    except Exception as e:
        print e
        raise InvalidPatch('invalid elf')

    for offset in diff:
        vaddr = e.offset_to_vaddr(offset)
        if vaddr is None:
            raise InvalidPatch('patch at offset %#x is not valid' % (offset))
        func = None
        for k, f in e.functions.iteritems():
            if f.address <= vaddr < f.address + f.size:
                func = f
                break
        if func is None:
            raise InvalidPatch('patch at offset %#x is not in a valid function' % (offset))
        if 'babi' not in func.name:
            raise InvalidPatch('patch at offset %#x(%s+%#x) is not part of main program' % (
                offset, func.name, vaddr - func.address))
        for kw in BLACKLIST:
            if kw in func.name:
                raise InvalidPatch('patch at offset %#x(%s+%#x) is not allowed' % (offset,
                    func.name, vaddr - func.address))
        print 'patching %#x(%s+%#x) [%#x] => [%#x]' % (offset, 
                func.name, vaddr - func.address, ord(b[offset]), ord(a[offset]))

    print 'all good'
    sys.exit(0)
except Exception as e:
    print 'PUBLIC: %s' % e
    sys.exit(1)
