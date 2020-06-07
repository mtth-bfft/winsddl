#!/usr/bin/env python3

import argparse
import ctypes
import string
import platform
import sys
from typing import Optional
from sid import SID
from acl import ACL
from accessmask import AccessMask
from utils.color import propagate_colors


class SD:

    def __init__(self, raw: str, owner: Optional[SID] = None, primary_group: Optional[SID] = None,
                 dacl: Optional[ACL] = None, sacl: Optional[ACL] = None):
        self.raw = raw
        self.owner = owner
        self.primary_group = primary_group
        self.dacl = dacl
        self.sacl = sacl

    def to_str(self, with_color: bool = sys.stdin.isatty()) -> str:
        s = ''
        if self.owner is not None:
            s += '\n    Owner: ' + self.owner.to_str(with_color=with_color)
        if self.primary_group is not None:
            s += '\n    Primary group: ' + self.primary_group.to_str(with_color=with_color)
        if self.dacl is not None:
            s += '\n    Discretionary ACL: ' + '\n    '.join(self.dacl.to_str().split('\n'))
        if self.sacl is not None:
            s += '\n    System ACL: ' + '\n    '.join(self.sacl.to_str().split('\n'))
        if with_color:
            s = propagate_colors(self.raw, s) + s
        else:
            s = self.raw + s
        return s

    @classmethod
    def from_str(cls, raw: str, access_mask_cls: type = AccessMask):
        # Detect binary security descriptors and convert them to string
        # security descriptors, to process them just like others
        raw = raw.strip()
        if len(raw) > 0 and all(c in string.hexdigits for c in raw):
            raw = cls.str_from_hexstring(raw)
        # Parse 'raw' as a SDDL string
        left = raw
        owner = primary_group = dacl = sacl = None
        if left[:2].upper() == 'O:':
            end_pos = left.find(':', 2)
            if end_pos < 0:
                end_pos = len(left) + 1
            owner, left = left[2:end_pos - 1], left[end_pos-1:]
        if left[:2].upper() == 'G:':
            end_pos = left.find(':', 2)
            if end_pos < 0:
                end_pos = len(left) + 1
            primary_group, left = left[2:end_pos - 1], left[end_pos - 1:]
        if left[:2].upper() == 'D:':
            end_pos = left.find(':', 2)
            if end_pos < 0:
                end_pos = len(left) + 1
            dacl, left = left[2:end_pos - 1], left[end_pos - 1:]
        if left[:2].upper() == 'S:':
            end_pos = left.find(':', 2)
            if end_pos < 0:
                end_pos = len(left) + 1
            sacl, left = left[2:end_pos - 1], left[end_pos - 1:]
        return cls(raw,
                   None if owner is None else SID.from_str(owner),
                   None if primary_group is None else SID.from_str(primary_group),
                   None if dacl is None else ACL.from_str(dacl, access_mask_cls=access_mask_cls),
                   None if sacl is None else ACL.from_str(sacl, access_mask_cls=access_mask_cls))

    @classmethod
    def str_from_hexstring(cls, hexstring: str) -> str:
        if platform.system() != 'Windows':
            raise RuntimeError("Cannot parse hex string as security descriptor on non-Windows hosts")
        sd_bytes = (ctypes.c_uint8 * (int(len(hexstring) / 2)))(*(int(hexstring[i:i+2], 16) for i in range(0, len(hexstring), 2)))
        sd_str = ctypes.c_wchar_p(0)
        sd_str_len = ctypes.c_uint32(0)
        res = ctypes.windll.advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(ctypes.byref(sd_bytes),
                                                                                          1,
                                                                                          ctypes.c_uint8(-1),
                                                                                          ctypes.byref(sd_str),
                                                                                          ctypes.byref(sd_str_len))
        if res == 0:
            return None
        res = ctypes.wstring_at(sd_str)[::]
        ctypes.windll.kernel32.LocalFree(sd_str)
        return res

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Parser and formatter for SDDL')
    parser.add_argument('sd', nargs='+')
    parser.add_argument('--format', '-f', choices=['sddl', 'multiline'], default='multiline')
    parser.add_argument('--type', '-t', choices=AccessMask.TYPES.keys())
    args = parser.parse_args()
    for sd in args.sd:
        sd = SD.from_str(sd, access_mask_cls=AccessMask.get_cls(args.type))
        print(sd.to_str())
