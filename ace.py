#!/usr/bin/env python3

import argparse
from typing import Optional
from sid import SID
from accessmask import AccessMask
from accessmasks.mandatory_label_policy import MandatoryLabelPolicy
from utils.color import colorize


class ACE:

    def __init__(self, acestr: str, acetype: Optional[str] = None, flags = None,
            rights: Optional[AccessMask] = None, object_guid: Optional[str] = None,
            inherit_object_guid: Optional[str] = None, trustee: Optional[SID] = None,
            resource_attribute: Optional[str] = None):
        self.acestr = acestr
        self.acetype = acetype
        self.flags = flags
        self.rights = rights
        self.object_guid = object_guid
        self.inherit_object_guid = inherit_object_guid
        self.trustee = trustee
        self.resource_attribute = resource_attribute

    def to_str(self, with_color: bool = True) -> str:
        s = self.acestr
        if self.acetype is not None:
            if with_color:
                s += '\n    Type: ' + colorize(self.acetype)
            else:
                s += '\n    Type: ' + self.acetype
            if self.acetype in self.TYPES:
                s += f' ({self.TYPES[self.acetype]})'
            else:
                s += f' (unknown ACE type)'
        if self.flags is not None and len(self.flags) > 0:
            s += f'\n    Flags: '
            if with_color:
                s += '\n           '.join(f'{colorize(abbr)}: {props[0]} ({props[1]})' for abbr, props in self.flags.items())
            else:
                s += '\n           '.join(f'{abbr}: {props[0]} ({props[1]})' for abbr, props in self.flags.items())
        if self.rights is not None:
            s += '\n    Access rights: ' + '\n    '.join(self.rights.to_str().split('\n'))
        s += f'\n    Trustee: {self.trustee.to_str(True, True, True)}'
        return s

    @classmethod
    def from_str(cls, raw: str, access_mask_cls: type = AccessMask):
        raw = raw.strip()
        acestr = raw
        if raw[0] == '(' and raw[-1] == ')':
            raw = raw[1:-1]
        while raw.count(';') < 6:
            raw += ';'
        acetype, raw_flags, rights, obj_guid, inherit_guid, trustee, resource_attr = raw.split(';', 6)
        acetype = acetype.upper()
        # Microsoft piggybacked on SACLs to implement MAC: cross-level policies reuse access right bits
        if acetype == 'ML':
            access_mask_cls = MandatoryLabelPolicy
        rights = access_mask_cls.from_str(rights)
        trustee = SID.from_str(trustee)
        flags = {}
        raw_flags = raw_flags.upper()
        while len(raw_flags) > 0:
            for abbr, props in cls.FLAGS.items():
                if raw_flags.startswith(abbr):
                    flags[abbr] = props
                    raw_flags = raw_flags[len(abbr):]
                    break
            else:
                flags[raw_flags] = ('?', '?')
                break
        return cls(acestr, acetype, flags, rights, obj_guid, inherit_guid, trustee, resource_attr)


ACE.TYPES = {
    'A': 'ACCESS_ALLOWED_ACE_TYPE',
    'D': 'ACCESS_DENIED_ACE_TYPE',
    'OA': 'ACCESS_ALLOWED_OBJECT_ACE_TYPE',
    'OD': 'ACCESS_DENIED_OBJECT_ACE_TYPE',
    'AU': 'SYSTEM_AUDIT_ACE_TYPE',
    'AL': 'SYSTEM_ALARM_ACE_TYPE',
    'OU': 'SYSTEM_AUDIT_OBJECT_ACE_TYPE',
    'OL': 'SYSTEM_ALARM_OBJECT_ACE_TYPE',
    'ML': 'SYSTEM_MANDATORY_LABEL_ACE_TYPE',
    'XA': 'ACCESS_ALLOWED_CALLBACK_ACE_TYPE',
    'XD': 'ACCESS_DENIED_CALLBACK_ACE_TYPE',
    'RA': 'SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE',
    'SP': 'SYSTEM_SCOPED_POLICY_ID_ACE_TYPE',
    'XU': 'SYSTEM_AUDIT_CALLBACK_ACE_TYPE',
    'ZA': 'ACCESS_ALLOWED_CALLBACK_ACE_TYPE',
}
ACE.FLAGS = {
    'CI': ('CONTAINER_INHERIT_ACE', 'ACE is inherited by container objects'),
    'OI': ('OBJECT_INHERIT_ACE', 'ACE is inherited by non-container objects'),
    'NP': ('NO_PROPAGATE_INHERIT_ACE', 'ACE inheritance flags are cleared when inherited'),
    'IO': ('INHERIT_ONLY_ACE', 'ACE does not apply to this container, only its children'),
    'ID': ('INHERITED_ACE', 'ACE is inherited from a parent container'),
    'SA': ('SUCCESSFUL_ACCESS_ACE_FLAG', 'Successful use of these access rights generates an event'),
    'FA': ('FAILED_ACCESS_ACE_FLAG', 'Denied use of these access rights generates an event'),
}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Parser and formatter for ACE strings')
    parser.add_argument('ace')
    parser.add_argument('--format', '-f', choices=['ace', 'multiline'], default='multiline')
    parser.add_argument('--type', '-t', choices=AccessMask.TYPES.keys())
    args = parser.parse_args()
    ace = ACE.from_str(args.ace, access_mask_cls=AccessMask.get_cls(args.type))
    print(ace.to_str(multiline=args.format == 'multiline'))
