#!/usr/bin/env python3

import argparse
from typing import Optional, List
from ace import ACE
from accessmask import AccessMask


class ACL:

    def __init__(self, aclstr: str, flags: Optional[List[str]] = None, aces: Optional[List[ACE]] = None):
        self.aclstr = aclstr
        self.flags = flags
        self.aces = aces

    def to_str(self, with_color: bool = True) -> str:
        s = self.aclstr
        if self.flags is not None and len(self.flags) > 0:
            s += f'\n    Flags: '
            s += '\n           '.join(f'{abbr}: {props[0]} ({props[1]})' for abbr, props in self.flags.items())
        for ace in [] if self.aces is None else self.aces:
            s += '\n\n    ACE: ' + '\n    '.join(ace.to_str(with_color).split('\n'))
        return s

    @classmethod
    def from_str(cls, raw: str, access_mask_cls: type = AccessMask):
        raw = raw.strip()
        flags = {}
        left = raw
        ace_start = raw.find('(')
        if ace_start > 0:
            raw_flags, left = raw[:ace_start].upper(), raw[ace_start:]
            while len(raw_flags) > 0:
                for abbr, props in cls.FLAGS.items():
                    if raw_flags.startswith(abbr):
                        flags[abbr] = props
                        raw_flags = raw_flags[len(abbr):]
                        break
                else:
                    flags[raw_flags] = ('', 'Unknown flag')
                    raw_flags = ''
        aces = None
        if left == '' or (left[0] == '(' and left[-1] == ')'):
            aces = []
            for ace in left[1:-1].split(')('):
                aces.append(ACE.from_str(ace, access_mask_cls=access_mask_cls))
        return cls(raw, flags, aces)


ACL.FLAGS = {
    'P': ('SE_DACL_PROTECTED', 'Blocks inheritance of parent\'s ACEs'),
    'AR': ('SE_DACL_AUTO_INHERIT_REQ', 'ACEs should be automatically propagated to children'),
    'AI': ('SE_DACL_AUTO_INHERITED', 'ACEs are automatically propagated to children'),
    'NO_ACCESS_CONTROL': ('', '/!\\ There is no ACL, access is always granted, except for AppContainers'),
}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Parser and formatter for ACL strings')
    parser.add_argument('acl')
    parser.add_argument('--format', '-f', choices=['sddl', 'multiline'], default='multiline')
    parser.add_argument('--type', '-t', choices=AccessMask.TYPES.keys())
    args = parser.parse_args()
    acl = ACL.from_str(args.acl, access_mask_cls=AccessMask.get_cls(args.type))
    print(acl.to_str(multiline=args.format == 'multiline'))
