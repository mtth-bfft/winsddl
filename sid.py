#!/usr/bin/env python3

import argparse
import platform
import ctypes
from typing import Optional
from utils.color import colorize


class SID:

    def __init__(self, raw: str, sid: Optional[str] = None, principal: Optional[str] = None,
                 abbr: Optional[str] = None, desc: Optional[str] = None):
        self.raw = raw
        self.sid = sid
        self.principal = principal
        self.abbr = abbr
        self.desc = desc

    def to_str(self, sid: bool = True, principal: bool = True, abbr: bool = True, desc: bool = True, with_color: bool = True) -> str:
        s = ''
        if sid and self.sid is not None and self.sid != self.raw.upper():
            s += f' ({self.sid})'
        if principal and self.principal is not None and self.principal.upper() != self.raw.upper():
            s += f' ({self.principal})'
        if abbr and self.abbr is not None and self.raw.upper() != self.raw:
            s += f' ({self.abbr})'
        if desc and self.desc is not None:
            s += f' ({self.desc})'
        if with_color:
            s = colorize(self.raw) + s
        else:
            s = self.raw + s

        return s

    @classmethod
    def from_str(cls, raw: str):
        raw = raw.strip()
        upper = raw.upper()
        for wellknown in cls.WELL_KNOWN_SIDS:
            if '<domain-sid>' in wellknown.raw:
                prefix, suffix = wellknown.raw.split('<domain-sid>')
            elif '<root-domain-sid>' in wellknown.raw:
                prefix, suffix = wellknown.raw.split('<root-domain-sid>')
            else:
                prefix, suffix = '', wellknown.sid
            # Does the input match this well known SID's SID
            if upper.startswith(prefix) and upper.endswith(suffix):
                return cls(upper, wellknown.sid, wellknown.principal, wellknown.abbr, wellknown.desc)
            # Does the input match this well known SID's SDDL abbreviation
            if upper == wellknown.abbr:
                return cls(upper, wellknown.sid, wellknown.principal, wellknown.abbr, wellknown.desc)
            # Does the input match this well known SID's account name
            if wellknown.principal is not None and upper == wellknown.principal.upper():
                return cls(wellknown.principal, wellknown.sid, wellknown.principal, wellknown.abbr, wellknown.desc)
        # Does the input look like a SID we could try to resolve
        if upper.startswith('S-'):
            return cls(upper, upper, cls.resolve_to_name(upper), None, None)
        # Last resort: try to resolve the input like an account name
        return cls(raw, cls.resolve_from_name(raw), raw, None, None)

    @classmethod
    def resolve_from_name(cls, account_name: str) -> Optional[str]:
        if platform.system() != 'Windows':
            return None
        account_name_buf = ctypes.create_unicode_buffer(account_name)
        sid_len = ctypes.c_uint32(0)
        domain_name_len = ctypes.c_uint32(0)
        sid_name_use = ctypes.c_uint32(0)
        res = ctypes.windll.advapi32.LookupAccountNameW(None, account_name_buf, None, ctypes.byref(sid_len), None,
                                                        ctypes.byref(domain_name_len), ctypes.byref(sid_name_use))
        if res != 0 or ctypes.GetLastError() != 122: # ERROR_INSUFFICIENT_BUFFER
            return None
        sid_buf = (ctypes.c_byte * sid_len.value)()
        domain_name_buf = (ctypes.c_byte * domain_name_len.value)()
        res = ctypes.windll.advapi32.LookupAccountNameW(None, account_name_buf, ctypes.byref(sid_buf), ctypes.byref(sid_len),
                                                        domain_name_buf, ctypes.byref(domain_name_len),
                                                        ctypes.byref(sid_name_use))
        if res == 0:
            return None
        resolved_name = ctypes.c_wchar_p(0)
        res = ctypes.windll.advapi32.ConvertSidToStringSidW(sid_buf, ctypes.byref(resolved_name))
        if res == 0:
            return None
        res = ctypes.wstring_at(resolved_name)[::]
        ctypes.windll.kernel32.LocalFree(resolved_name)
        return res

    @classmethod
    def resolve_to_name(self, sidstr: str) -> Optional[str]:
        if platform.system() != 'Windows':
            return None
        sid_str_buf = ctypes.create_unicode_buffer(sidstr)
        sid_ptr = ctypes.c_void_p(0)
        res = ctypes.windll.advapi32.ConvertStringSidToSidW(sid_str_buf, ctypes.byref(sid_ptr))
        if res == 0 or sid_ptr.value == 0:
            return None
        user_name_len = ctypes.c_uint32(0)
        domain_name_len = ctypes.c_uint32(0)
        sid_name_use = ctypes.c_uint32(0)
        res = ctypes.windll.advapi32.LookupAccountSidW(None, sid_ptr, None, ctypes.byref(user_name_len), None,
                                                       ctypes.byref(domain_name_len), ctypes.byref(sid_name_use))
        if res != 0 or ctypes.GetLastError() != 122:  # ERROR_INSUFFICIENT_BUFFER
            return None
        user_name_buf = (ctypes.c_wchar * user_name_len.value)()
        domain_name_buf = (ctypes.c_wchar * domain_name_len.value)()
        res = ctypes.windll.advapi32.LookupAccountSidW(None, sid_ptr, user_name_buf, ctypes.byref(user_name_len),
                                                       domain_name_buf, ctypes.byref(domain_name_len),
                                                       ctypes.byref(sid_name_use))
        if res == 0:
            return None
        res = ctypes.wstring_at(user_name_buf)
        domain_name = ctypes.wstring_at(domain_name_buf)
        if domain_name != '':
            res = domain_name + '\\' + res
        ctypes.windll.kernel32.LocalFree(sid_ptr)
        return res


SID.AUTHORITIES = {
    0: 'NULL AUTHORITY',
    1: 'WORLD AUTHORITY',
    2: 'LOCAL AUTHORITY',
    3: 'CREATOR AUTHORITY',
    4: 'NON UNIQUE AUTHORITY',
    5: 'NT AUTHORITY',
    9: 'RESOURCE MANAGER AUTHORITY',
    15: 'APPLICATION PACKAGE AUTHORITY',
}

# See https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems
# and https://docs.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
# (/!\ there might be typos in these pages, e.g. they mix up S-1-5-15 and S-1-5-17)
SID.WELL_KNOWN_SIDS = [
    SID('', 'S-1-0-0', 'Nobody', None,
        'No security principal -be careful, users can have this SID enabled in their token-'),
    SID('', 'S-1-1-0', 'Everyone', 'WD',
        'Authenticated users, Guests, and Anonymous remote users in XP SP1 and earlier, ' +
        'or if EveryoneIncludesAnonymous=1'),
    SID('', 'S-1-2-0', 'Local', None,
        'Group that includes all users who have logged on locally'),
    SID('', 'S-1-2-1', 'Console Logon', None,
        'Group that includes all users who have logged on to the physical console, added in Windows 7 / 2008 R2'),
    SID('', 'S-1-3-0', 'Creator Owner', 'CO',
        "Placeholder in an inheritable access control entry, replaced when inherited with the child object's " +
        "creator's SID"),
    SID('', 'S-1-3-1', 'Creator Group', 'CG',
        "Placeholder in an inheritable access control entry, replaced when inherited with the child object's " +
        "creator's primary group SID"),
    SID('', 'S-1-3-4', 'Owner Rights', None,
        'Placeholder replaced with the owner of the object. When an ACE with this SID is present, ' +
        'READ_CONTROL and WRITE_DAC are not implicitly granted to the owner'),
    SID('', 'S-1-5-1', 'Dialup', None,
        'Group that includes all users who have logged on through a dialup connection, maintained by the system'),
    SID('', 'S-1-5-2', 'Network', 'NU',
        'Group that includes all users who have logged on through a network connection, maintained by the system'),
    SID('', 'S-1-5-3', 'Batch', None,
        'Group that includes all users who have logged on through a batch queue facility, maintained by the system'),
    SID('', 'S-1-5-4', 'Interactive', 'IU',
        'Group that includes all users who have logged on interactively, maintained by the system'),
    SID('', 'S-1-5-6', 'Service Logon', 'SU',
        'Group that includes all security principals who have logged as a service, maintained by the system'),
    SID('', 'S-1-5-7', 'Anonymous Logon', 'AN',
        'Group that includes all users who have logged on anonymously, maintained by the system'),
    SID('', 'S-1-5-9', 'Enterprise Domain Controllers', 'ED',
        'Group that contains all the domain controllers in an Active Directory forest, maintained by the system'),
    SID('', 'S-1-5-10', 'Principal Self', 'PS'
        "Placeholder in an inheritable access control entry, replaced when inherited by a User or Group" +
        "with the child object's SID"),
    SID('', 'S-1-5-11', 'Authenticated Users', 'AU'),
    SID('', 'S-1-5-12', 'Restricted Code', 'RC'),
    SID('', 'S-1-5-13', 'Terminal Services Users', None,
        'Group that includes all users who have logged on to a Terminal Services server, maintained by the system'),
    SID('', 'S-1-5-14', 'Remote Interactive Logon', None,
        'Group that includes all users who have logged on through a terminal services logon, maintained by the system'),
    SID('', 'S-1-5-15', 'This Organization', None,
        'Group that includes all users from the same Organization, maintained by the system'),
    SID('', 'S-1-5-17', 'IUSR', 'IS',
        'Internet Information Services (IIS)-specific user'),
    SID('', 'S-1-5-18', 'Local System', 'SY'),
    SID('', 'S-1-5-19', 'Local Service', 'LS'),
    SID('', 'S-1-5-20', 'Network Service', 'NS'),
    SID('', 'S-1-5-21-<domain-sid>-498', 'Enterprise Read-only Domain Controllers', 'RO'),
    SID('', 'S-1-5-21-<domain-sid>-500', 'Administrator', 'LA'),
    SID('', 'S-1-5-21-<domain-sid>-501', 'Guest', 'LG'),
    SID('', 'S-1-5-21-<domain-sid>-502', 'KRBTGT', None),
    SID('', 'S-1-5-21-<domain-sid>-512', 'Domain Administrators', 'DA'),
    SID('', 'S-1-5-21-<domain-sid>-513', 'Domain Users', 'DU'),
    SID('', 'S-1-5-21-<domain-sid>-514', 'Domain Guests', 'DG'),
    SID('', 'S-1-5-21-<domain-sid>-515', 'Domain Computers', 'DC'),
    SID('', 'S-1-5-21-<domain-sid>-516', 'Domain Controllers', 'DD'),
    SID('', 'S-1-5-21-<domain-sid>-517', 'Certificate Publishers', 'CA'),
    SID('', 'S-1-5-21-<domain-sid>-520', 'Group Policy Creator Owners', 'PA'),
    SID('', 'S-1-5-21-<domain-sid>-521', 'Read-only Domain Controllers', None,
        'Global group that contains this domain\'s readonly Domain Controllers'),
    SID('', 'S-1-5-21-<domain-sid>-522', 'Cloneable Domain Controllers', None),
    SID('', 'S-1-5-21-<domain-sid>-526', 'Key Admins', None),
    SID('', 'S-1-5-21-<domain-sid>-527', 'Enterprise Key Admins', None),
    SID('', 'S-1-5-21-<domain-sid>-553', 'RAS and IAS Servers', 'RS'),
    SID('', 'S-1-5-21-<domain-sid>-571', 'Allowed RODC Password Replication Group', None),
    SID('', 'S-1-5-21-<domain-sid>-572', 'Denied RODC Password Replication Group', None),
    SID('', 'S-1-5-21-<domain-sid>-575', 'RDS Remote Access Servers', None),
    SID('', 'S-1-5-21-<domain-sid>-576', 'RDS Endpoint Servers', None),
    SID('', 'S-1-5-21-<domain-sid>-577', 'RDS Management Servers', None),
    SID('', 'S-1-5-21-<domain-sid>-578', 'Hyper-V Administrators', None),
    SID('', 'S-1-5-21-<domain-sid>-579', 'Access Control Assistance Operators', None),
    SID('', 'S-1-5-21-<domain-sid>-580', 'Remote Management Users', None),
    SID('', 'S-1-5-21-<root-domain-sid>-518', 'Schema Administrators', 'SA'),
    SID('', 'S-1-5-21-<root-domain-sid>-519', 'Enterprise Admins', 'EA'),
    SID('', 'S-1-5-32-544', 'Administrators', 'BA'),
    SID('', 'S-1-5-32-545', 'Users', 'BU'),
    SID('', 'S-1-5-32-546', 'Guests', 'BG'),
    SID('', 'S-1-5-32-547', 'Power Users', 'PU'),
    SID('', 'S-1-5-32-548', 'Account Operators', 'AO'),
    SID('', 'S-1-5-32-549', 'Server Operators', 'SO'),
    SID('', 'S-1-5-32-550', 'Print Operators', 'PO'),
    SID('', 'S-1-5-32-551', 'Backup Operators', 'BO'),
    SID('', 'S-1-5-32-552', 'Replicators', 'RE'),
    SID('', 'S-1-5-32-554', 'Pre-Windows 2000 Compatible Access', 'RU'),
    SID('', 'S-1-5-32-555', 'Remote Desktop Users', 'RD'),
    SID('', 'S-1-5-32-556', 'Network Configuration Operators', 'NO'),
    SID('', 'S-1-5-32-557', 'Incoming Forest Trust Builders', None,
        'Members of this group can create incoming, one-way trusts to this forest'),
    SID('', 'S-1-5-32-558', 'Performance Monitor Users', 'MU'),
    SID('', 'S-1-5-32-559', 'Performance Log Users', 'LU'),
    SID('', 'S-1-5-32-560', 'Windows Authorization Access Group', None),
    SID('', 'S-1-5-32-561', 'Terminal Server License Servers', None),
    SID('', 'S-1-5-32-562', 'Distributed COM Users', None),
    SID('', 'S-1-5-32-569', 'Cryptographic Operators', None),
    SID('', 'S-1-5-32-573', 'Event Log Readers', None),
    SID('', 'S-1-5-32-574', 'Certificate Service DCOM Access', 'CD',
        'Users who can connect to certificate authorities using DCOM'),
    SID('', 'S-1-5-64-10', 'NTLM Authentication', None),
    SID('', 'S-1-5-64-14', 'SChannel Authentication', None),
    SID('', 'S-1-5-64-21', 'Digest Authentication', None),
    SID('', 'S-1-5-80-0', 'All Services', None,
        'Group that represents all service processes running, added in Windows Vista and Server 2008 R2'),
    SID('', 'S-1-5-83-0', 'Virtual Machines', None),
    SID('', 'S-1-15-2-1', 'All Application Packages', 'AC'),
    SID('', 'S-1-15-2-2', 'All Restricted Application Packages', None),
    SID('', 'S-1-16-0', 'Untrusted Integrity Level', None),
    SID('', 'S-1-16-4096', 'Low Integrity Level', 'LW'),
    SID('', 'S-1-16-8192', 'Medium Integrity Level', 'ME'),
    SID('', 'S-1-16-8448', 'Medium Plus Integrity Level', None),
    SID('', 'S-1-16-12288', 'High Integrity Level', 'HI'),
    SID('', 'S-1-16-16384', 'System Integrity Level', 'SI'),
    SID('', 'S-1-16-20480', 'Protected Process Integrity Level', None),
    SID('', 'S-1-16-28672', 'Secure Process Integrity Level', None),
]

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Resolver for well-known SID')
    parser.add_argument('sid')
    parser.add_argument('--format', '-f', choices=['sid', 'resolved', 'abbreviated', 'all'], default='all')
    args = parser.parse_args()
    sid = SID.from_str(args.sid)
    print(sid.to_str(
        resolve=(args.format in ('resolved','all')),
        abbr=(args.format in ('abbreviated','all')),
        desc=(args.format == 'all')))
