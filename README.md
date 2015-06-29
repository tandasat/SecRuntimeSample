# SecRuntimeSample
A sample usage of unsupported Win32 APIs and SecRuntime.dll on Windows Phone. 
It lists other processes' information using those raw APIs and backdoor APIs 
implemented in SecRuntime.dll.

## Installation

Get an archive file for compiled files form this link on your PC:

    https://github.com/tandasat/SecRuntimeSample/releases/latest

Then, deploy the application using the Application Deployment tool. See 
[MSDN - Deploy Windows Phone apps with the Application Deployment tool]
(https://msdn.microsoft.com/en-us/library/dn632395.aspx).

## Usage

It shows a list of processes on the phone. It is not possible using only 
supported Win32 APIs, but you can still call unsupported APIs including 
functions exported from any of exotic dlls.

Output will look like this:

     392    304  2015-06-28      13:39:08  \\NT AUTHORITY\SYSTEM             System      C:\Windows\system32\WININIT.EXE
     636    408  2015-06-28      13:39:09  \\NT AUTHORITY\SYSTEM             System      C:\Windows\system32\SVCHOST.EXE
     672    408  2015-06-28      13:39:10  \\NT AUTHORITY\NETWORK SERVICE    System      C:\Windows\system32\SVCHOST.EXE
     752    408  2015-06-28      13:39:10  \\NT AUTHORITY\SYSTEM             System      C:\Windows\system32\SVCHOST.EXE
     792    408  2015-06-28      13:39:10  \\NT AUTHORITY\SYSTEM             System      C:\Windows\system32\SVCHOST.EXE
     840    408  2015-06-28      13:39:11  \\Windows Phone\WPCRITICAL        High        C:\Windows\system32\SVCHOST.EXE
     864    408  2015-06-28      13:39:11  \\NT AUTHORITY\LOCAL SERVICE      System      C:\Windows\system32\SVCHOST.EXE
     900    408  2015-06-28      13:39:11  \\Windows Phone\WPNETWORK         High        C:\Windows\system32\SVCHOST.EXE
     920    408  2015-06-28      13:39:11  \\NT AUTHORITY\SYSTEM             System      C:\Windows\system32\SVCHOST.EXE
     936    408  2015-06-28      13:39:11  \\NT AUTHORITY\SYSTEM             System      C:\Windows\system32\SVCHOST.EXE
     952    408  2015-06-28      13:39:11  \\NT AUTHORITY\LOCAL SERVICE      System      C:\Windows\system32\SVCHOST.EXE
    1104    408  2015-06-28      13:39:12  \\Windows Phone\DefApps           High        C:\Windows\system32\SVCHOST.EXE
    1232    408  2015-06-28      13:39:13  \\NT AUTHORITY\NETWORK SERVICE    System      C:\Windows\system32\SVCHOST.EXE
    1296    408  2015-06-28      13:39:13  \\NT AUTHORITY\LOCAL SERVICE      System      C:\Windows\system32\SVCHOST.EXE
    1356    408  2015-06-28      13:39:14  \\Windows Phone\WPNONETWORK       High        C:\Windows\system32\SVCHOST.EXE
    1380    408  2015-06-28      13:39:14  \\NT AUTHORITY\SYSTEM             System      C:\Windows\system32\SVCHOST.EXE
    1420    408  2015-06-28      13:39:14  \\Windows Phone\NSGEXTUTI         High        C:\Windows\system32\OEMServiceHost.exe
    1436    408  2015-06-28      13:39:14  \\NT AUTHORITY\SYSTEM             System      C:\Windows\system32\OEMServiceHost.exe
    1476    408  2015-06-28      13:39:14  \\Windows Phone\NGPSVC            High        C:\Windows\system32\ngp_svc.exe
    1548    408  2015-06-28      13:39:14  \\Windows Phone\QCSHUTDOWNSVC     High        C:\Windows\system32\QcShutdownSvc8626.exe
    1568    408  2015-06-28      13:39:14  \\NT AUTHORITY\SYSTEM             System      C:\Windows\system32\SVCHOST.EXE
    1584    408  2015-06-28      13:39:14  \\NT AUTHORITY\SYSTEM             System      C:\Windows\system32\RILAdaptationService.exe
    1620    408  2015-06-28      13:39:15  \\Windows Phone\WPCOMMSSERVICES   High        C:\Windows\system32\SVCHOST.EXE
    1640    408  2015-06-28      13:39:15  \\NT AUTHORITY\SYSTEM             System      C:\Windows\system32\SVCHOST.EXE
    1704    408  2015-06-28      13:39:15  \\Windows Phone\DefApps           High        C:\Windows\system32\SVCHOST.EXE
    1884    936  2015-06-28      13:39:15  \\Windows Phone\DefApps           Low         C:\Windows\system32\MobileUI.exe
    2036    408  2015-06-28      13:39:16  \\Windows Phone\IPOVERUSBGROUP    High        C:\Windows\system32\SVCHOST.EXE
    1368    936  2015-06-28      13:39:20  \\Windows Phone\DefApps           Low         C:\PROGRAMS\START\starthost.exe
    2020    936  2015-06-28      13:39:21  \\Windows Phone\DefApps           Low         C:\Windows\system32\HeadlessHost.exe
    2252    408  2015-06-28      13:39:22  \\NT AUTHORITY\SYSTEM             System      C:\Windows\system32\OEMServiceHost.exe
    2292    408  2015-06-28      13:39:23  \\Windows Phone\NSGEXTBSP         High        C:\Windows\system32\OEMServiceHost.exe
    2456    408  2015-06-28      13:39:23  \\NT AUTHORITY\SYSTEM             System      C:\Windows\system32\OEMServiceHost.exe
    2656    408  2015-06-28      13:39:24  \\NT AUTHORITY\SYSTEM             System      C:\Windows\system32\eMMCClnrSvc.exe
    2732    408  2015-06-28      13:39:24  \\Windows Phone\FEEDBACKSVC       High        C:\Windows\system32\OEMServiceHost.exe
    2768    408  2015-06-28      13:39:25  \\NT AUTHORITY\SYSTEM             System      C:\Windows\system32\OEMServiceHost.exe
    2816    408  2015-06-28      13:39:25  \\Windows Phone\NOKIARCSESVC      High        C:\Windows\system32\rcsesvc.exe
    3612    792  2015-06-28      13:40:02  \\NT AUTHORITY\SYSTEM             System      C:\Windows\system32\WLANEXT.EXE
    3640    792  2015-06-28      13:40:02  \\NT AUTHORITY\LOCAL SERVICE      System      C:\Windows\system32\WUDFHOST.EXE
    4076   1380  2015-06-28      13:40:38  \\Windows Phone\DefApps           Low         C:\PROGRAMS\HOTSPOTHOST\HotspotHost.exe
    3108    936  2015-06-28      13:58:21  \\Windows Phone\DefApps           Low         C:\PROGRAMS\COMMSAPPLICATIONS\Email.exe
    2604    936  2015-06-28      17:38:00  \\Windows Phone\DefApps           Low         C:\Windows\system32\TaskHost.exe
    2228    936  2015-06-28      17:47:11  \\Windows Phone\DefApps           Low         C:\Windows\system32\TaskHost.exe
    1172    936  2015-06-28      18:38:48  \\NT AUTHORITY\SYSTEM             System      C:\PROGRAMS\DEVICEREG\DeviceReg.exe
    3332    636  2015-06-28      18:39:04  \\Windows Phone\DefApps           Low         U:\PROGRAMS\WINDOWSAPPS\7c5c9e7f-2643-45d5-94a2-02ff6ee9e249_1.0.0.5_arm__yzekw4x8qxe1g\CopyFiles.exe
    2940    900  2015-06-28      19:21:27  \\Windows Phone\DefApps           Low         U:\SharedData\PhoneTools\11.0\CoreCon\bin\ConManClient3.exe
    3900   2940  2015-06-28      19:21:30  \\Windows Phone\DefApps           Low         U:\SharedData\PhoneTools\11.0\CoreCon\bin\edm3.exe
     740   3900  2015-06-28      19:25:18  \\Windows Phone\DefApps           Low         \Device\HarddiskVolume27\SharedData\PhoneTools\11.0\Debugger\bin\RemoteDebugger\msvsmon.exe
    2672   3900  2015-06-28      19:25:22  \\Windows Phone\DefApps           Low         \Device\HarddiskVolume27\SharedData\PhoneTools\11.0\Debugger\bin\RemoteDebugger\msvsmon.exe
    1892    636  2015-06-28      19:31:38  \\Windows Phone\DefApps           Low         U:\SharedData\PhoneTools\AppxLayouts\1bbebe6a-4291-4988-bb67-0f53c11eea58VS.Debug_ARM.user\SecRuntimeSample.exe

## Acknowledgment

The icon was made by [dAKirby309](http://www.iconarchive.com/show/windows-8-metro-icons-by-dakirby309/Apps-GIMP-Metro-icon.html). 
Thank you for releasing this lovely icon under the flexible license.

![ICON](/img/120.png)

## Supported Platform(s)

Windows Phone 8.1

## License

This software is released under the MIT License, see LICENSE.
