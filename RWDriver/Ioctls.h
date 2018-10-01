// IOCTLS.H -- IOCTL code definitions for fileio driver
// Copyright (C) 1999 by Walter Oney
// All rights reserved

#ifndef IOCTLS_H
#define IOCTLS_H

#ifndef CTL_CODE
	#pragma message("CTL_CODE undefined. Include winioctl.h or wdm.h")
#endif

#define IOCTL_READ CTL_CODE(\
			FILE_DEVICE_UNKNOWN, \
			0x800, \
			METHOD_BUFFERED, \
			FILE_ANY_ACCESS)

#define IOCTL_WRITE CTL_CODE(\
			FILE_DEVICE_UNKNOWN, \
			0x801, \
            METHOD_BUFFERED, \
			FILE_ANY_ACCESS)

#define IOCTL_GETIMAGE CTL_CODE(\
			FILE_DEVICE_UNKNOWN, \
			0x802, \
            METHOD_BUFFERED, \
			FILE_ANY_ACCESS)

#define IOCTL_HIDE_PROCESS CTL_CODE(\
    FILE_DEVICE_UNKNOWN, \
    0x803, \
    METHOD_BUFFERED, \
    FILE_ANY_ACCESS)

#define IOCTL_RESTORE_PROCESS CTL_CODE(\
    FILE_DEVICE_UNKNOWN, \
    0x804, \
    METHOD_BUFFERED, \
    FILE_ANY_ACCESS)

#define IOCTL_HIDE_DRIVER CTL_CODE(\
    FILE_DEVICE_UNKNOWN, \
    0x805, \
    METHOD_BUFFERED, \
    FILE_ANY_ACCESS)

#define IOCTL_RESTORE_DRIVER CTL_CODE(\
    FILE_DEVICE_UNKNOWN, \
    0x806, \
    METHOD_BUFFERED, \
    FILE_ANY_ACCESS)

#endif
