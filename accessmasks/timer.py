#!/usr/bin/env python3

from accessmask import AccessMask, main


class TimerAccessMask(AccessMask):

    VALID_RIGHTS = 0x1F0003

    RIGHTS = [
        {'abbr': 'GR', 'name': 'GENERIC_READ', 'val': 0x80000000, 'desc': 'Generic right to read, mapped to TIMER_QUERY_STATE | READ_CONTROL'},
        {'abbr': 'GW', 'name': 'GENERIC_WRITE', 'val': 0x40000000, 'desc': 'Generic right to write, mapped to TIMER_MODIFY_STATE | READ_CONTROL'},
        {'abbr': 'GX', 'name': 'GENERIC_EXECUTE', 'val': 0x20000000, 'desc': 'Generic right to execute, mapped to SYNCHRONIZE | READ_CONTROL'},
        {'abbr': 'GA', 'name': 'GENERIC_ALL', 'val': 0x10000000, 'desc': 'Generic right mapped to every other existing right'},
        {'abbr': None, 'name': 'TIMER_ALL_ACCESS', 'val': 0x1F0003, 'desc': 'All timer rights that existed when the requestor was compiled'},
        {'abbr': 'CC', 'name': 'TIMER_QUERY_STATE', 'val': 0x1, 'desc': 'Reserved for future use'},
        {'abbr': 'DC', 'name': 'TIMER_MODIFY_STATE', 'val': 0x2, 'desc': 'Set this timer'},
    ]


AccessMask.TYPES['timer'] = TimerAccessMask

if __name__ == '__main__':
    main(TimerAccessMask)
