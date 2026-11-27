; PktPath Studio — per-user (no UAC) NSIS installer
; Unicode. Built on Linux (makensis) or GitHub Actions windows-latest.
;
; Required defines (Ning / package_preview_bundle.py interface):
;   -DAPP_VERSION=<ver>        default 0.0.0-preview
;   -DSTAGING_DIR=<dir>        install root payload (PktPathStudio.exe, node\,
;                              studio-cordis\, collectors\, LICENSE, LICENSES\,
;                              MANIFEST.sha256). Do not include .cmd/.ps1.
;   -DOUT_FILE=<path.exe>
;
; Optional:
;   -DICON_FILE=<path.ico>

!ifndef APP_VERSION
  !define APP_VERSION "0.0.0-preview"
!endif
!ifndef STAGING_DIR
  !ifdef STAGE_DIR
    !define STAGING_DIR "${STAGE_DIR}"
  !else
    !error "STAGE_DIR (or STAGING_DIR) is required (payload directory)"
  !endif
!endif
!ifndef OUT_FILE
  !error "OUT_FILE is required (Setup .exe path)"
!endif
!ifndef ICON_FILE
  !define ICON_FILE "${__FILEDIR__}/../assets/pktpath-studio.ico"
!endif

!include "MUI2.nsh"
!include "FileFunc.nsh"
!include "LogicLib.nsh"
!include "WordFunc.nsh"
!include "x64.nsh"

!insertmacro GetSize
!insertmacro un.WordReplace

Unicode True
SetCompressor /SOLID lzma
RequestExecutionLevel user

Name "PktPath Studio"
BrandingText "PktPath Studio ${APP_VERSION}"
OutFile "${OUT_FILE}"
InstallDir "$LOCALAPPDATA\Programs\PktPath Studio"
InstallDirRegKey HKCU "Software\PktPath\Studio" "InstallDir"

VIProductVersion "0.0.0.0"
VIAddVersionKey /LANG=0 "ProductName" "PktPath Studio"
VIAddVersionKey /LANG=0 "FileDescription" "PktPath Studio Setup"
VIAddVersionKey /LANG=0 "FileVersion" "${APP_VERSION}"
VIAddVersionKey /LANG=0 "ProductVersion" "${APP_VERSION}"
VIAddVersionKey /LANG=0 "LegalCopyright" "Copyright The PktPath Authors. Licensed under the Apache License 2.0."
VIAddVersionKey /LANG=0 "OriginalFilename" "PktPath-Studio-Setup.exe"
VIAddVersionKey /LANG=0 "CompanyName" "PktPath"

!define TRAY_WINDOW_CLASS "PktPathStudioTrayWindowClass"
!ifndef WM_CLOSE
  !define WM_CLOSE 0x0010
!endif
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\PktPathStudio"
!define SETTINGS_KEY "Software\PktPath\Studio"

!define MUI_ICON "${ICON_FILE}"
!define MUI_UNICON "${ICON_FILE}"
!define MUI_ABORTWARNING
!define MUI_LANGDLL_REGISTRY_ROOT "HKCU"
!define MUI_LANGDLL_REGISTRY_KEY "${SETTINGS_KEY}"
!define MUI_LANGDLL_REGISTRY_VALUENAME "InstallerLanguage"

!define MUI_FINISHPAGE_RUN "$INSTDIR\PktPathStudio.exe"
!define MUI_FINISHPAGE_RUN_TEXT "$(FinishRunText)"
!define MUI_FINISHPAGE_NOREBOOTSUPPORT

!insertmacro MUI_PAGE_LICENSE "${STAGING_DIR}\LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "SimpChinese"
!insertmacro MUI_LANGUAGE "English"

LangString FinishRunText ${LANG_SIMPCHINESE} "立即启动 PktPath Studio"
LangString FinishRunText ${LANG_ENGLISH} "Launch PktPath Studio now"
LangString CloseTimeoutText ${LANG_SIMPCHINESE} "PktPath Studio 仍在运行。请先从托盘图标选择「退出」后再继续安装或卸载。"
LangString CloseTimeoutText ${LANG_ENGLISH} "PktPath Studio is still running. Please choose Exit from the tray icon, then retry the install or uninstall."
LangString AlreadyRunningText ${LANG_SIMPCHINESE} "正在关闭已运行的 PktPath Studio…"
LangString AlreadyRunningText ${LANG_ENGLISH} "Closing the running PktPath Studio instance…"

; Wait up to 24s (240 * 100ms) for the tray host to complete graceful
; shutdown (QuitWait=16s + ForceKillWait=3s + safety margin).
!macro CloseRunningStudio
  Push $0
  Push $1
  Push $2
  StrCpy $1 0
  StrCpy $2 0
  loop:
    FindWindow $0 "${TRAY_WINDOW_CLASS}" ""
    StrCmp $0 0 done
    IntCmp $1 1 wait
    SendMessage $0 ${WM_CLOSE} 0 0 /TIMEOUT=2000
    StrCpy $1 1
  wait:
    IntCmp $2 240 timeout
    Sleep 100
    IntOp $2 $2 + 1
    Goto loop
  timeout:
    IfSilent +2
    MessageBox MB_OK|MB_ICONEXCLAMATION "$(CloseTimeoutText)"
    Pop $2
    Pop $1
    Pop $0
    Abort
  done:
    ; Extra beat so file handles can drop after the window disappears.
    Sleep 200
    Pop $2
    Pop $1
    Pop $0
!macroend

; Remove parent directories of a relative path bottom-up using non-recursive
; RMDir (only deletes directories that are completely empty, preserving any
; user files stored inside $INSTDIR).
; Input on stack: relative path using backslashes (e.g. "node\node.exe").
Function un.PruneEmptyParents
  Exch $0 ; $0 = current relative path
  Push $1 ; length
  Push $2 ; cursor index
  Push $3 ; char

  prune_outer:
    StrLen $1 $0
    StrCpy $2 $1
  find_sep:
    IntCmp $2 0 prune_done prune_done 0
    IntOp $2 $2 - 1
    StrCpy $3 $0 1 $2
    StrCmp $3 "\" found_sep
    Goto find_sep
  found_sep:
    IntCmp $2 0 prune_done prune_done 0
    StrCpy $0 $0 $2
    RMDir "$INSTDIR\$0"
    Goto prune_outer

  prune_done:
  Pop $3
  Pop $2
  Pop $1
  Pop $0
FunctionEnd

; Delete only the files listed in $INSTDIR\MANIFEST.sha256 and prune any
; directories that become empty. Never uses recursive directory deletion so
; unrelated user files sharing $INSTDIR cannot be deleted.
Function un.DeleteManifestFiles
  Push $0 ; file handle
  Push $1 ; raw line
  Push $2 ; relative path
  Push $3 ; scratch / separator check
  Push $4 ; length / last char

  IfFileExists "$INSTDIR\MANIFEST.sha256" 0 manifest_done
  FileOpen $0 "$INSTDIR\MANIFEST.sha256" r
  IfErrors manifest_done

  read_next:
    ClearErrors
    FileRead $0 $1
    IfErrors read_close

    ; Strip trailing CR/LF.
  strip_eol:
    StrLen $4 $1
    IntCmp $4 0 read_next read_next 0
    IntOp $4 $4 - 1
    StrCpy $3 $1 1 $4
    StrCmp $3 "$\r" do_strip
    StrCmp $3 "$\n" do_strip
    Goto parse_line
  do_strip:
    StrCpy $1 $1 $4
    Goto strip_eol

  parse_line:
    ; Format: "<64-hex-sha256>  <relative/path>"
    StrLen $4 $1
    IntCmp $4 67 0 read_next 0
    StrCpy $3 $1 2 64
    StrCmp $3 "  " 0 read_next
    StrCpy $2 $1 "" 66
    StrCmp $2 "" read_next

    ; Normalize POSIX slashes to Windows backslashes.
    ${un.WordReplace} "$2" "/" "\" "+" $2

    ; Reject absolute paths, drive letters, and parent traversal ("..").
    StrCpy $3 $2 1
    StrCmp $3 "\" read_next
    ${un.WordReplace} "$2" ":" "" "+" $3
    StrCmp $3 $2 0 read_next
    StrCmp $2 ".." read_next
    StrCpy $3 $2 3
    StrCmp $3 "..\" read_next
    ${un.WordReplace} "$2" "\..\" "" "+" $3
    StrCmp $3 $2 0 read_next
    StrCpy $3 $2 3 -3
    StrCmp $3 "\.." read_next

    Delete "$INSTDIR\$2"
    Push $2
    Call un.PruneEmptyParents
    Goto read_next

  read_close:
    FileClose $0

  manifest_done:
  Pop $4
  Pop $3
  Pop $2
  Pop $1
  Pop $0
FunctionEnd

Function .onInit
  SetShellVarContext current
  !insertmacro MUI_LANGDLL_DISPLAY
  !insertmacro CloseRunningStudio
FunctionEnd

Function un.onInit
  SetShellVarContext current
  !insertmacro MUI_UNGETLANGUAGE
  !insertmacro CloseRunningStudio
FunctionEnd

Section "PktPath Studio" SecApp
  SetShellVarContext current
  !insertmacro CloseRunningStudio

  SetOutPath "$INSTDIR"
  File /r "${STAGING_DIR}\*.*"

  WriteUninstaller "$INSTDIR\Uninstall.exe"

  CreateDirectory "$SMPROGRAMS\PktPath Studio"
  CreateShortCut "$SMPROGRAMS\PktPath Studio\PktPath Studio.lnk" "$INSTDIR\PktPathStudio.exe" "" "$INSTDIR\PktPathStudio.exe" 0
  CreateShortCut "$SMPROGRAMS\PktPath Studio\卸载 PktPath Studio.lnk" "$INSTDIR\Uninstall.exe" "" "$INSTDIR\Uninstall.exe" 0
  CreateShortCut "$DESKTOP\PktPath Studio.lnk" "$INSTDIR\PktPathStudio.exe" "" "$INSTDIR\PktPathStudio.exe" 0

  WriteRegStr HKCU "${SETTINGS_KEY}" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayName" "PktPath Studio"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayVersion" "${APP_VERSION}"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "Publisher" "PktPath"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayIcon" "$INSTDIR\PktPathStudio.exe"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKCU "${UNINSTALL_KEY}" "QuietUninstallString" '"$INSTDIR\Uninstall.exe" /S'
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoRepair" 1
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "EstimatedSize" 0
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "EstimatedSize" $0
SectionEnd

Section "Uninstall"
  SetShellVarContext current
  !insertmacro CloseRunningStudio

  ; Remove shortcuts and installed files listed in MANIFEST.sha256 only.
  ; NEVER delete %LOCALAPPDATA%\PktPathStudio (sessions, logs, plugins, config),
  ; and NEVER use recursive RMDir on $INSTDIR so user files remain untouched.
  Delete "$DESKTOP\PktPath Studio.lnk"
  Delete "$SMPROGRAMS\PktPath Studio\PktPath Studio.lnk"
  Delete "$SMPROGRAMS\PktPath Studio\卸载 PktPath Studio.lnk"
  RMDir "$SMPROGRAMS\PktPath Studio"

  Call un.DeleteManifestFiles
  Delete "$INSTDIR\MANIFEST.sha256"
  Delete "$INSTDIR\PktPathStudio.exe"
  Delete "$INSTDIR\Uninstall.exe"
  ; Non-recursive: removes $INSTDIR only if completely empty.
  RMDir "$INSTDIR"

  DeleteRegKey HKCU "${UNINSTALL_KEY}"
  DeleteRegKey HKCU "${SETTINGS_KEY}"
SectionEnd
