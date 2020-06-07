#!/usr/bin/env python3

import argparse
import re
from typing import Optional
from utils.color import colorize


class AccessMask:

    TYPES = {
        # Filled by subclasses
    }

    RIGHTS = [
        {'abbr': 'GR', 'name': 'GENERIC_READ', 'val': 0x80000000, 'desc': 'Generic right to read, mapped to type-specific rights'},
        {'abbr': 'GW', 'name': 'GENERIC_WRITE', 'val': 0x40000000, 'desc': 'Generic right to write, mapped to type-specific rights'},
        {'abbr': 'GX', 'name': 'GENERIC_EXECUTE', 'val': 0x20000000, 'desc': 'Generic right to execute, mapped to type-specific rights'},
        {'abbr': 'GA', 'name': 'GENERIC_ALL', 'val': 0x10000000, 'desc': 'Generic right mapped to every other existing right'},
        {'abbr': 'RC', 'name': 'READ_CONTROL', 'val': 0x20000, 'desc': 'Read the object\'s security descriptor except its SACL, standard to all types'},
        {'abbr': 'SD', 'name': 'DELETE', 'val': 0x10000, 'desc': 'Delete the object, standard to all types'},
        {'abbr': 'WD', 'name': 'WRITE_DAC', 'val': 0x40000, 'desc': 'Replace this DACL, standard to all types'},
        {'abbr': 'WO', 'name': 'WRITE_OWNER', 'val': 0x80000, 'desc': 'Replace the object\'s owner, standard to all types'},
        {'abbr': None, 'name': 'SYNCHRONIZE', 'val': 0x100000, 'desc': 'Wait for a change in the object, standard to all types'},
        {'abbr': 'AS', 'name': 'ACCESS_SYSTEM_SECURITY', 'val': 0x1000000, 'desc': 'Read and write SACL, standard to all types, can be used in SACL, not DACL'},
        {'abbr': None, 'name': 'STANDARD_RIGHTS_EXECUTE', 'val': 0x20000, 'desc': 'Mapped to READ_CONTROL'},
        {'abbr': None, 'name': 'STANDARD_RIGHTS_READ', 'val': 0x20000, 'desc': 'Mapped to READ_CONTROL'},
        {'abbr': None, 'name': 'STANDARD_RIGHTS_WRITE', 'val': 0x20000, 'desc': 'Mapped to READ_CONTROL'},
        {'abbr': None, 'name': 'STANDARD_RIGHTS_REQUIRED', 'val': 0xF0000, 'desc': 'Rights supported by all object types: DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER'},
        {'abbr': None, 'name': 'STANDARD_RIGHTS_ALL', 'val': 0x1F0000, 'desc': 'All standard rights: DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER, SYNCHRONIZE'},
        {'abbr': 'WO', 'name': 'WRITE_OWNER', 'val': 0x80000, 'desc': 'Replace the object\'s owner, standard to all types'},
        # SDDL uses type-specific abbreviations are used no matter the original type
        # they were intended for, as a shortcut
        {'abbr': 'CC', 'name': '<TYPE-SPECIFIC BIT 0x1>', 'val': 1 << 0, 'desc': 'Type-specific bit 0x1'},
        {'abbr': 'DC', 'name': '<TYPE SPECIFIC BIT 0x2>', 'val': 1 << 1, 'desc': 'Type-specific bit 0x2'},
        {'abbr': 'LC', 'name': '<TYPE SPECIFIC BIT 0x4>', 'val': 1 << 2, 'desc': 'Type-specific bit 0x4'},
        {'abbr': 'SW', 'name': '<TYPE SPECIFIC BIT 0x8>', 'val': 1 << 3, 'desc': 'Type-specific bit 0x8'},
        {'abbr': 'RP', 'name': '<TYPE SPECIFIC BIT 0x10>', 'val': 1 << 4, 'desc': 'Type-specific bit 0x10'},
        {'abbr': 'WP', 'name': '<TYPE SPECIFIC BIT 0x20>', 'val': 1 << 5, 'desc': 'Type-specific bit 0x20'},
        {'abbr': 'DT', 'name': '<TYPE SPECIFIC BIT 0x40>', 'val': 1 << 6, 'desc': 'Type-specific bit 0x40'},
        {'abbr': 'LO', 'name': '<TYPE SPECIFIC BIT 0x80>', 'val': 1 << 7, 'desc': 'Type-specific bit 0x80'},
        {'abbr': 'CR', 'name': '<TYPE SPECIFIC BIT 0x100>', 'val': 1 << 8, 'desc': 'Type-specific bit 0x100'},
        {'abbr': 'FR', 'name': '<GENERIC BIT 0x80000000>', 'val': 0x80000000, 'desc': ''},
        {'abbr': 'FW', 'name': '<GENERIC BIT 0x40000000>', 'val': 0x40000000, 'desc': ''},
        {'abbr': 'FX', 'name': '<GENERIC BIT 0x20000000>', 'val': 0x20000000, 'desc': ''},
        {'abbr': 'FA', 'name': '<TYPE SPECIFIC BITS 0x1F01FF>', 'val': 0x1F01FF, 'desc': ''},
        {'abbr': 'KA', 'name': '<TYPE SPECIFIC BITS 0xF003F>', 'val': 0xF003F, 'desc': ''},
        {'abbr': 'KR', 'name': '<TYPE SPECIFIC BITS 0x20019>', 'val': 0x20019, 'desc': ''},
        {'abbr': 'KX', 'name': '<TYPE SPECIFIC BITS 0x20019>', 'val': 0x20019, 'desc': ''},
        {'abbr': 'KW', 'name': '<TYPE SPECIFIC BITS 0x20006>', 'val': 0x20006, 'desc': ''},
    ]

    def __init__(self, raw: str, rights: int):
        self.raw = raw
        self.rights = rights

    def to_str(self, with_color: bool = True) -> str:
        s = self.raw
        if with_color:
            s = colorize(s)
        if not self.raw.startswith('0x'):
            s += '\t(0x{:X})'.format(self.rights)
        remaining = self.rights
        for bit in range(31, -1, -1):
            val = 1 << bit
            if (remaining & val) == 0:
                continue
            remaining &= ~val
            for right in self.RIGHTS + AccessMask.RIGHTS:
                if right['val'] == val:
                    s += f"\n    0x{'{:X}'.format(val):<8} {right['name']}\t({right['desc']})"
                    break
            else:
                s += '\n    <Unknown {} right 0x{:X}>'.format(self.get_bit_type(bit), val)
        return s

    def to_sddl(self) -> str:
        s = ''
        remaining = self.rights
        prev_remaining = -1
        while remaining > 0 and remaining != prev_remaining:
            prev_remaining = remaining
            for right in self.RIGHTS:
                if (right['val'] & remaining) == right['val'] and right['abbr'] is not None:
                    s += right['abbr']
                    remaining &= ~right['val']
                    break
            for right in AccessMask.RIGHTS:
                if (right['val'] & remaining) == right['val'] and right['abbr'] is not None:
                    s += right['abbr']
                    remaining &= ~right['val']
                    break
        if remaining > 0:
            return '0x{:X}'.format(self.rights)
        return s

    @classmethod
    def get_cls(cls, objtype: Optional[str]) -> type:
        if objtype is not None:
            objtype = objtype.lower().strip()
        if objtype in cls.TYPES:
            return cls.TYPES[objtype]
        return AccessMask

    @classmethod
    def get_bit_type(cls, pos: int) -> str:
        if 31 >= pos >= 28:
            return 'generic'
        elif 27 >= pos >= 25:
            return 'reserved'
        elif 24 >= pos >= 16:
            return 'standard'
        elif 15 >= pos >= 0:
            return 'type-specific'

    @classmethod
    def from_str(cls, raw: str):
        rights = 0
        for unparsed in filter(None, re.split(r'[ ,|+]', raw.strip().upper())):
            try:
                rights |= int(unparsed, 0)
                continue
            except ValueError:
                pass
            for flag in (cls.RIGHTS + AccessMask.RIGHTS):
                if unparsed == flag['name']:
                    rights |= flag['val']
                    unparsed = ''
                    break
            while len(unparsed) > 0:
                for flag in (cls.RIGHTS + AccessMask.RIGHTS):
                    if flag['abbr'] is not None and unparsed.startswith(flag['abbr']):
                        rights |= flag['val']
                        unparsed = unparsed[len(flag['abbr']):]
                        break
                else:
                    raise ValueError(f'Unknown access right "{unparsed}"')
        return cls(raw, rights)


def main(cls: type):
    parser = argparse.ArgumentParser(description='Parser and formatter for access right masks')
    parser.add_argument('accessmask')
    parser.add_argument('--format', '-f', choices=['hex', 'sddl', 'multiline'], default='multiline')
    args = parser.parse_args()
    mask = cls.from_str(args.accessmask)
    if args.format == 'hex':
        print('0x{:X}'.format(mask.rights))
    elif args.format == 'sddl':
        print(mask.to_sddl())
    elif args.format == 'multiline':
        print(mask.to_str(multiline=True))

# Always import subclasses of AccessMask so they get a chance to register themselves
# in the TYPES dictionary (needs to be after the AccessMask/main definition to resolve circular import)
from accessmasks import *

if __name__ == '__main__':
    main(AccessMask)
