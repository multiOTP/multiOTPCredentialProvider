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
 * @version   5.6.1.5
 * @date      2019-10-23
 * @since     2013
 * @copyright (c) 2016-2019 SysCo systemes de communication sa
 * @copyright (c) 2015-2016 ArcadeJust ("RDP only" enhancement)
 * @copyright (c) 2013-2015 Last Squirrel IT 
 * @copyright Apache License, Version 2.0
 *
 *
 * Change Log
 *
 *   2019-10-23 5.6.1.5 SysCo/al FIX: Prefix password parameter was buggy (better handling of parameters in debug mode)
 *                               FIX: swprintf_s problem with special chars (thanks to anekix)
 *   2019-01-25 5.4.1.6 SysCo/al FIX: Username with space are now supported
 *                               ENH: Added integrated Visual C++ 2017 Redistributable installation
 *   2018-09-14 5.4.0.1 SysCo/al FIX: Better domain name and hostname detection
 *                               FIX: The cache lifetime check process was buggy since 5.3.0.3
 *                               ENH: multiOTP Credential Provider files and objects have been reorganized
 *   2018-08-26 5.3.0.3 SysCo/al FIX: Users without 2FA token are now supported
 *   2018-08-21 5.3.0.0 SysCo/yj FIX: Save flat domain name in the registry. While offline, use this value instead of asking the DC
 *                      SysCo/al ENH: The multiOTP timeout (how long the Credential Provider wait a response from
 *                                    the multiOTP process) is now 60 seconds by default (instead of 10)
 *   2018-03-11 5.2.0.0 SysCo/al New implementation from scratch
 *
 *********************************************************************/
 
// 5fd3d285-0dd9-4362-8855-e0abaacd4af6
// DEFINE_GUID(CLSID_Multiotp, 0x5fd3d285, 0x0dd9, 0x4362, 0x88, 0x55, 0xe0, 0xab, 0xaa, 0xcd, 0x4a, 0xf6);

// The GUID must be higher than the MS filter GUID! (https://social.msdn.microsoft.com/Forums/windowsdesktop/en-US/4134d896-85f5-460e-b621-c3b8acf3a1c9/credential-provider-icredentialprovidersetserialization-is-never-called?forum=windowsgeneraldevelopmentissues)

// FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978
DEFINE_GUID(CLSID_Multiotp, 0xfcefdfab, 0xb0a1, 0x4c4d, 0x8b, 0x2b, 0x4f, 0xf4, 0xe0, 0xa3, 0xd9, 0x78);
