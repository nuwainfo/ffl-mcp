; ffl-mcp Windows installer - NSIS MUI2
; Build via:  python build.py  (or --installer-only)
; The following defines are injected by build.py at compile time via /D flags:
;   APP_VERSION          e.g. 0.1.5
;   EXE_PATH             absolute path to dist\ffl-mcp.exe
;   INSTALL_SCRIPT_PATH  absolute path to build-cache\install-mcp.ps1
;   UNINSTALL_SCRIPT_PATH absolute path to build-cache\uninstall-mcp.ps1
;   OUTPUT_DIR           absolute path to dist/

Unicode True
SetCompressor /SOLID lzma
!include "MUI2.nsh"

; -- App metadata -------------------------------------------------------------
!define APP_NAME      "FastFileLink MCP"
!define APP_PUBLISHER "FastFileLink"
!define APP_URL       "https://fastfilelink.com"
!define MCP_SERVER    "ffl"
!define INSTALL_DIR   "$LOCALAPPDATA\Programs\ffl-mcp"
!define REG_KEY       "Software\Microsoft\Windows\CurrentVersion\Uninstall\ffl-mcp"

; -- MUI settings -------------------------------------------------------------
!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "${APP_NAME} Setup"
!define MUI_WELCOMEPAGE_TEXT  "This wizard will install ${APP_NAME} and register \
  it as an MCP server with Claude Desktop and Claude Code.$\n$\n\
  Click Install to continue."
!define MUI_FINISHPAGE_TITLE "Installation Complete"
!define MUI_FINISHPAGE_TEXT  "${APP_NAME} has been installed.$\n$\n\
  Please restart Claude Desktop or Claude Code to activate the MCP server."
!define MUI_FINISHPAGE_NOAUTOCLOSE

; -- Installer pages ----------------------------------------------------------
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

; -- Uninstaller pages --------------------------------------------------------
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; -- General ------------------------------------------------------------------
Name          "${APP_NAME}"
OutFile       "${OUTPUT_DIR}\ffl-mcp-setup.exe"
InstallDir    "${INSTALL_DIR}"
RequestExecutionLevel user
ShowInstDetails   show
ShowUninstDetails show

; -- Install ------------------------------------------------------------------
Section "Install"
  SetOutPath $INSTDIR
  File "${EXE_PATH}"
  File "${INSTALL_SCRIPT_PATH}"
  File "${UNINSTALL_SCRIPT_PATH}"

  DetailPrint "Registering MCP server with Claude Desktop / Claude Code..."
  nsExec::ExecToLog "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File $\"$INSTDIR\install-mcp.ps1$\" -InstallDir $\"$INSTDIR$\""

  WriteUninstaller "$INSTDIR\Uninstall.exe"

  WriteRegStr   HKCU "${REG_KEY}" "DisplayName"    "${APP_NAME}"
  WriteRegStr   HKCU "${REG_KEY}" "DisplayVersion" "${APP_VERSION}"
  WriteRegStr   HKCU "${REG_KEY}" "Publisher"      "${APP_PUBLISHER}"
  WriteRegStr   HKCU "${REG_KEY}" "UninstallString" "$INSTDIR\Uninstall.exe"
  WriteRegStr   HKCU "${REG_KEY}" "DisplayIcon"    "$INSTDIR\ffl-mcp.exe"
  WriteRegStr   HKCU "${REG_KEY}" "URLInfoAbout"   "${APP_URL}"
  WriteRegDWORD HKCU "${REG_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${REG_KEY}" "NoRepair"  1
SectionEnd

; -- Uninstall ----------------------------------------------------------------
Section Uninstall
  DetailPrint "Removing MCP server registration..."
  nsExec::ExecToLog "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File $\"$INSTDIR\uninstall-mcp.ps1$\""

  DetailPrint "Cleaning PyApp cache..."
  RMDir /r "$LOCALAPPDATA\pyapp\data\ffl-mcp"

  DetailPrint "Removing files..."
  Delete "$INSTDIR\ffl-mcp.exe"
  Delete "$INSTDIR\install-mcp.ps1"
  Delete "$INSTDIR\uninstall-mcp.ps1"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir  "$INSTDIR"

  DeleteRegKey HKCU "${REG_KEY}"
SectionEnd
