#!/usr/bin/env python3

from accessmask import AccessMask, main


class JobAccessMask(AccessMask):

    VALID_RIGHTS = 0x1F003F

    RIGHTS = [
        {'abbr': 'GR', 'name': 'GENERIC_READ', 'val': 0x80000000, 'desc': 'Generic right to read, mapped to JOB_OBJECT_QUERY | READ_CONTROL'},
        {'abbr': 'GW', 'name': 'GENERIC_WRITE', 'val': 0x40000000, 'desc': 'Generic right to write, mapped to JOB_OBJECT_ASSIGN_PROCESS | JOB_OBJECT_SET_ATTRIBUTE | JOB_OBJECT_TERMINATE | READ_CONTROL'},
        {'abbr': 'GX', 'name': 'GENERIC_EXECUTE', 'val': 0x20000000, 'desc': 'Generic right to execute, mapped to SYNCHRONIZE | READ_CONTROL'},
        {'abbr': 'GA', 'name': 'GENERIC_ALL', 'val': 0x10000000, 'desc': 'Generic right mapped to every other existing right'},
        {'abbr': None, 'name': 'JOB_OBJECT_ALL_ACCESS', 'val': 0x1F001F, 'desc': 'All job rights that existed when the requestor was compiled'},
        {'abbr': 'CC', 'name': 'JOB_OBJECT_ASSIGN_PROCESS', 'val': 0x1, 'desc': 'Put a process inside that job (also requires PROCESS_SET_QUOTA and PROCESS_TERMINATE on the process)'},
        {'abbr': 'DC', 'name': 'JOB_OBJECT_SET_ATTRIBUTES', 'val': 0x2, 'desc': 'Set resource and security restrictions of the job'},
        {'abbr': 'LC', 'name': 'JOB_OBJECT_QUERY', 'val': 0x4, 'desc': 'Query resource and security restrictions of the job, and query if a process is in it (also requires PROCESS_QUERY_LIMITED_INFORMATION on the process)'},
        {'abbr': 'SW', 'name': 'JOB_OBJECT_TERMINATE', 'val': 0x8, 'desc': 'Terminate all processes in the job'},
        { 'abbr': 'RP', 'name': 'JOB_OBJECT_SET_SECURITY_ATTRIBUTES', 'val': 0x10, 'desc': 'Only in Windows XP and Server 2003, set JobObjectSecurityLimitInformation'},
    ]


AccessMask.TYPES['job'] = JobAccessMask

if __name__ == '__main__':
    main(JobAccessMask)
