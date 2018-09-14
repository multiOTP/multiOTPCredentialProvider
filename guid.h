/**
 * BASE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
 * ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
 * PARTICULAR PURPOSE.
 *
 * Copyright (c) Microsoft Corporation. All rights reserved.
 *
 * Extra code provided "as is" for the multiOTP open source project
 *
 * @author    Andre Liechti, SysCo systemes de communication sa, <info@multiotp.net>
 * @version   5.2.0.0
 * @date      2018-03-11
 * @since     2013
 * @copyright (c) 2016-2018 SysCo systemes de communication sa
 * @copyright (c) 2015-2016 ArcadeJust ("RDP only" enhancement)
 * @copyright (c) 2013-2015 Last Squirrel IT 
 * @copyright Apache License, Version 2.0
 *
 *
 * Change Log
 *
 *   2018-03-11 5.2.0.0 SysCo/al New implementation from scratch
 *
 *********************************************************************/
 
// 5fd3d285-0dd9-4362-8855-e0abaacd4af6
// DEFINE_GUID(CLSID_Multiotp, 0x5fd3d285, 0x0dd9, 0x4362, 0x88, 0x55, 0xe0, 0xab, 0xaa, 0xcd, 0x4a, 0xf6);

// The GUID must be higher than the MS filter GUID! (https://social.msdn.microsoft.com/Forums/windowsdesktop/en-US/4134d896-85f5-460e-b621-c3b8acf3a1c9/credential-provider-icredentialprovidersetserialization-is-never-called?forum=windowsgeneraldevelopmentissues)

// FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978
DEFINE_GUID(CLSID_Multiotp, 0xfcefdfab, 0xb0a1, 0x4c4d, 0x8b, 0x2b, 0x4f, 0xf4, 0xe0, 0xa3, 0xd9, 0x78);
