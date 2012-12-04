;----------------------------------------------------------------------------
;    MODULE NAME:   pjctl.mm
;
;        $Author:   USER "Benjamin Franzke"  $
;      $Revision:   1  $
;          $Date:   04 Dec 2012 15.15:00  $
;
;----------------------------------------------------------------------------


;--- Include MAKEMSI support (with my customisations and MSI branding) ------
;#define VER_FILENAME.VER  TryMe.Ver      ;;I only want one VER file for all samples! (this line not actually required in "tryme.mm")

#define? DEPT_ARP_URL_PUBLISHER           http://git.bnfr.net/pjctl
#define? DEPT_ARP_URL_TECHNICAL_SUPPORT   benjaminfranzke@googlemail.com
#define? DEPT_NAME                        Benjamin Franzke
#define? DEPT_ADDRESS                     ;;
#define? COMPANY_CONTACT_NAME             <$DEPT_NAME>
#define? COMPANY_CONTACT_NAME_PHONE                ;;No phone
#define? COMPANY_SUMMARY_SCHEMA           110      ;;Minimum v1.1 Installer

#define? UISAMPLE_LEFTSIDE_TEXT_FONT_COLOR         &H7F0000  ;;Medium Blue in BGR (believe it or not...)
#(
    #define? UISAMPLE_LEFTSIDE_TEXT
    Developed by <$DEPT_NAME>.
#)

#include "ME.MMH"
;#define? COMMONFRAMEWORK_ZIP_SOURCE_FOR_BACKUP     N         ;;No "insurance" until I bother to install "info zip"...
;#include "DEPT.MMH"

;--- Want to debug (not common) ---------------------------------------------
;#debug on
;#Option DebugLevel=^NONE, +OpSys^


;--- Define default location where file should install and add files --------
<$DirectoryTree Key="INSTALLDIR" Dir="c:\program files\pjctl\" CHANGE="\" PrimaryFolder="Y">
<$Files "pjctl-no-console.exe" DestDir="INSTALLDIR">
<$Files "pjctl.exe" DestDir="INSTALLDIR">
<$Files "C:\cygwin\bin\cygwin1.dll" DestDir="INSTALLDIR">