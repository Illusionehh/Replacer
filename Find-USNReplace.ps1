#requires -RunAsAdministrator

<#
.SYNOPSIS
    USN Replace Detector v4 - Italiano

.DESCRIPTION
    Analisi forense del journal USN NTFS.
    Supporta intestazioni CSV italiane e inglesi.

    Explorer:
    1. FILE_DELETE + CLOSE
    2. Se il primario non trova risultati:
       RENAME_OLD_NAME + CLOSE

    I risultati sono indicatori, non prove conclusive.
#>

param(
    [ValidatePattern("^[A-Za-z]:$")]
    [string]$Drive = "C:",

    [string]$OutputCsv = (
        Join-Path $env:USERPROFILE "Desktop\usn_replace_findings.csv"
    )
)

$ErrorActionPreference = "Stop"

# ============================================================
# BANNER
# ============================================================

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "          USN REPLACE DETECTOR" -ForegroundColor Cyan
Write-Host "              VERSIONE 4" -ForegroundColor Cyan
Write-Host "          made by illusionehh" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# ============================================================
# USN FLAGS
# ============================================================

$USN = [ordered]@{
    DATA_OVERWRITE        = [int64]1
    DATA_EXTEND           = [int64]2
    DATA_TRUNCATION       = [int64]4

    NAMED_DATA_OVERWRITE  = [int64]16
    NAMED_DATA_EXTEND     = [int64]32
    NAMED_DATA_TRUNCATION = [int64]64

    FILE_CREATE           = [int64]256
    FILE_DELETE           = [int64]512

    SECURITY_CHANGE       = [int64]2048

    RENAME_OLD_NAME       = [int64]4096
    RENAME_NEW_NAME       = [int64]8192

    BASIC_INFO_CHANGE     = [int64]32768

    CLOSE                 = [int64]2147483648
}

# ============================================================
# FUNZIONI
# ============================================================

function Convert-ToReasonInt64 {
    param([object]$Value)

    if ($null -eq $Value) {
        return $null
    }

    $text = ([string]$Value).Trim()

    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    try {
        if ($text -match '^0x[0-9a-fA-F]+$') {
            return [int64](
                [Convert]::ToInt64($text.Substring(2), 16)
            )
        }

        $number = [int64]$text

        if ($number -lt 0) {
            return $number + 4294967296
        }

        return $number
    }
    catch {
        return $null
    }
}

function Test-ReasonMask {
    param(
        [int64]$Reason,
        [int64[]]$RequiredFlags
    )

    $required = [int64]0

    foreach ($flag in $RequiredFlags) {
        $required = $required -bor $flag
    }

    return (($Reason -band $required) -eq $required)
}

function Get-ReasonNames {
    param([int64]$Reason)

    $names = @()

    foreach ($entry in $USN.GetEnumerator()) {
        $flag = [int64]$entry.Value

        if (($Reason -band $flag) -eq $flag) {
            $names += $entry.Key
        }
    }

    return $names
}

function New-Pattern {
    param(
        [string]$Technique,
        [string]$Variant,
        [int64[]]$Required
    )

    return [PSCustomObject]@{
        Technique = $Technique
        Variant   = $Variant
        Required  = $Required
    }
}

# ============================================================
# PATTERN EXPLORER
# ============================================================

$ExplorerPrimary = New-Pattern `
    -Technique "Explorer" `
    -Variant "File Delete + Close" `
    -Required @($USN.FILE_DELETE, $USN.CLOSE)

$ExplorerFallback = New-Pattern `
    -Technique "Explorer" `
    -Variant "Rename Old Name + Close (fallback)" `
    -Required @($USN.RENAME_OLD_NAME, $USN.CLOSE)

$Patterns = @(
    $ExplorerPrimary

    (New-Pattern "Explorer" "Rename New Name" @(
        $USN.RENAME_NEW_NAME
    ))

    (New-Pattern "Explorer" "Rename New Name + Close" @(
        $USN.RENAME_NEW_NAME,
        $USN.CLOSE
    ))

    # TYPE 1

    (New-Pattern "Type 1" "Data Extend + Data Truncation" @(
        $USN.DATA_EXTEND,
        $USN.DATA_TRUNCATION
    ))

    (New-Pattern "Type 1" "Data Extend + Data Truncation + Close" @(
        $USN.DATA_EXTEND,
        $USN.DATA_TRUNCATION,
        $USN.CLOSE
    ))

    # TYPE 2

    (New-Pattern "Type 2" "Data Truncation" @(
        $USN.DATA_TRUNCATION
    ))

    (New-Pattern "Type 2" "Data Extend + Data Truncation" @(
        $USN.DATA_EXTEND,
        $USN.DATA_TRUNCATION
    ))

    # COPY 1

    (New-Pattern "Copy 1" "Data Truncation + Security Change" @(
        $USN.DATA_TRUNCATION,
        $USN.SECURITY_CHANGE
    ))

    (New-Pattern "Copy 1" "Data Extend + Truncation + Security" @(
        $USN.DATA_EXTEND,
        $USN.DATA_TRUNCATION,
        $USN.SECURITY_CHANGE
    ))

    (New-Pattern "Copy 1" "Overwrite + Extend + Truncation + Security" @(
        $USN.DATA_OVERWRITE,
        $USN.DATA_EXTEND,
        $USN.DATA_TRUNCATION,
        $USN.SECURITY_CHANGE
    ))

    (New-Pattern "Copy 1" "Overwrite + Extend + Truncation + Security + BasicInfo" @(
        $USN.DATA_OVERWRITE,
        $USN.DATA_EXTEND,
        $USN.DATA_TRUNCATION,
        $USN.SECURITY_CHANGE,
        $USN.BASIC_INFO_CHANGE
    ))

    (New-Pattern "Copy 1" "Overwrite + Extend + Truncation + Security + BasicInfo + Close" @(
        $USN.DATA_OVERWRITE,
        $USN.DATA_EXTEND,
        $USN.DATA_TRUNCATION,
        $USN.SECURITY_CHANGE,
        $USN.BASIC_INFO_CHANGE,
        $USN.CLOSE
    ))

    # COPY 2

    (New-Pattern "Copy 2" "Data Truncation" @(
        $USN.DATA_TRUNCATION
    ))

    (New-Pattern "Copy 2" "Data Extend + Data Truncation" @(
        $USN.DATA_EXTEND,
        $USN.DATA_TRUNCATION
    ))

    (New-Pattern "Copy 2" "Overwrite + Extend + Truncation" @(
        $USN.DATA_OVERWRITE,
        $USN.DATA_EXTEND,
        $USN.DATA_TRUNCATION
    ))

    (New-Pattern "Copy 2" "Overwrite + Extend + Truncation + BasicInfo" @(
        $USN.DATA_OVERWRITE,
        $USN.DATA_EXTEND,
        $USN.DATA_TRUNCATION,
        $USN.BASIC_INFO_CHANGE
    ))

    (New-Pattern "Copy 2" "Overwrite + Extend + Truncation + BasicInfo + Close" @(
        $USN.DATA_OVERWRITE,
        $USN.DATA_EXTEND,
        $USN.DATA_TRUNCATION,
        $USN.BASIC_INFO_CHANGE,
        $USN.CLOSE
    ))

    # HEX 1

    (New-Pattern "HEX 1" "Data Extend" @(
        $USN.DATA_EXTEND
    ))

    (New-Pattern "HEX 1" "Data Overwrite + Data Extend" @(
        $USN.DATA_OVERWRITE,
        $USN.DATA_EXTEND
    ))

    (New-Pattern "HEX 1" "Data Overwrite + Data Extend + Close" @(
        $USN.DATA_OVERWRITE,
        $USN.DATA_EXTEND,
        $USN.CLOSE
    ))

    # HEX 2

    (New-Pattern "HEX 2" "Data Overwrite + Data Extend" @(
        $USN.DATA_OVERWRITE,
        $USN.DATA_EXTEND
    ))

    (New-Pattern "HEX 2" "Data Overwrite + Data Extend + Close" @(
        $USN.DATA_OVERWRITE,
        $USN.DATA_EXTEND,
        $USN.CLOSE
    ))
)

# ============================================================
# VERIFICA DRIVE
# ============================================================

if (-not (Test-Path "$Drive\")) {
    Write-Host "[!] Drive non trovata: $Drive" -ForegroundColor Red
    exit 1
}

if (-not (Get-Command fsutil.exe -ErrorAction SilentlyContinue)) {
    Write-Host "[!] fsutil.exe non disponibile." -ForegroundColor Red
    exit 1
}

Write-Host "[*] Disco: $Drive" -ForegroundColor Gray
Write-Host "[*] CSV: $OutputCsv" -ForegroundColor Gray
Write-Host ""

# ============================================================
# LETTURA JOURNAL
# ============================================================

Write-Host "[*] Lettura journal USN..." -ForegroundColor Cyan

$raw = @(& fsutil.exe usn readjournal $Drive csv 2>&1)

if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Errore durante la lettura del journal." -ForegroundColor Red
    $raw | Select-Object -Last 10 | ForEach-Object { Write-Host $_ }
    exit 1
}

Write-Host "[+] Righe ricevute: $($raw.Count)" -ForegroundColor Green

# ============================================================
# RICERCA INTESTAZIONE CSV
# ============================================================

$headerIndex = -1

for ($i = 0; $i -lt $raw.Count; $i++) {
    $line = [string]$raw[$i]

    if ($line -match '^(?i)"?USN"?,') {
        $headerIndex = $i
        break
    }
}

if ($headerIndex -lt 0) {
    Write-Host "[!] Intestazione CSV non trovata." -ForegroundColor Red
    $raw | Select-Object -First 15 | ForEach-Object { Write-Host $_ }
    exit 1
}

Write-Host "[+] Intestazione trovata alla riga $headerIndex" -ForegroundColor Green

# ============================================================
# PARSING CSV
# ============================================================

$csvText = $raw[$headerIndex..($raw.Count - 1)] -join "`r`n"

try {
    $parsed = @($csvText | ConvertFrom-Csv)
}
catch {
    Write-Host "[!] Errore parsing CSV: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

if ($parsed.Count -eq 0) {
    Write-Host "[!] Nessun record interpretato." -ForegroundColor Red
    exit 1
}

# Normalizzazione tramite posizione delle colonne:
# 0 USN
# 1 nome file
# 3 motivo numerico
# 5 timestamp
# 8 ID file
# 9 ID file padre

$records = New-Object System.Collections.Generic.List[object]

foreach ($row in $parsed) {
    $properties = @($row.PSObject.Properties)

    if ($properties.Count -lt 10) {
        continue
    }

    $records.Add([PSCustomObject]@{
        Usn             = $properties[0].Value
        FileName        = $properties[1].Value
        Reason          = $properties[3].Value
        TimeStamp       = $properties[5].Value
        FileReference   = $properties[8].Value
        ParentReference = $properties[9].Value
    })
}

Write-Host "[+] Record interpretati: $($records.Count)" -ForegroundColor Green
Write-Host ""

if ($records.Count -eq 0) {
    Write-Host "[!] Nessun record utilizzabile." -ForegroundColor Red
    exit 1
}

# ============================================================
# ANALISI PRIMARIA
# ============================================================

$findings = New-Object System.Collections.Generic.List[object]

$processed = 0
$matches = 0
$explorerPrimaryMatches = 0

Write-Host "[*] Analisi dei bitmask..." -ForegroundColor Cyan

foreach ($record in $records) {
    $processed++

    $reason = Convert-ToReasonInt64 $record.Reason

    if ($null -eq $reason) {
        continue
    }

    foreach ($pattern in $Patterns) {
        if (-not (Test-ReasonMask `
            -Reason $reason `
            -RequiredFlags $pattern.Required)) {
            continue
        }

        $matches++

        # Conta soltanto il pattern FILE_DELETE + CLOSE.
        if ($pattern.Variant -eq "File Delete + Close") {
            $explorerPrimaryMatches++
        }

        $names = Get-ReasonNames $reason

        $findings.Add([PSCustomObject]@{
            TimeStamp       = $record.TimeStamp
            Technique       = $pattern.Technique
            Variant         = $pattern.Variant
            DetectionMode   = "Primary"
            FileName        = $record.FileName
            FileReference   = $record.FileReference
            ParentReference = $record.ParentReference
            USN             = $record.Usn
            ReasonDecimal   = $reason
            ReasonHex       = ("0x{0:X8}" -f $reason)
            ReasonsPresent  = $names -join " | "
            RequiredFlags   = (
                $pattern.Required | ForEach-Object {
                    "0x{0:X8}" -f $_
                }
            ) -join " | "
            Indicator       = "MATCH"
        })
    }

    if (($processed % 50000) -eq 0) {
        Write-Host "[*] Processati: $processed / $($records.Count)" -ForegroundColor DarkGray
    }
}

# ============================================================
# FALLBACK EXPLORER
# ============================================================

$fallbackMatches = 0

if ($explorerPrimaryMatches -eq 0) {
    Write-Host ""
    Write-Host "[!] Nessun match Explorer primario." -ForegroundColor Yellow
    Write-Host "[*] Avvio fallback RENAME_OLD_NAME + CLOSE..." -ForegroundColor Cyan

    foreach ($record in $records) {
        $reason = Convert-ToReasonInt64 $record.Reason

        if ($null -eq $reason) {
            continue
        }

        if (Test-ReasonMask `
            -Reason $reason `
            -RequiredFlags $ExplorerFallback.Required) {

            $fallbackMatches++
            $matches++

            $names = Get-ReasonNames $reason

            $findings.Add([PSCustomObject]@{
                TimeStamp       = $record.TimeStamp
                Technique       = "Explorer"
                Variant         = $ExplorerFallback.Variant
                DetectionMode   = "Fallback"
                FileName        = $record.FileName
                FileReference   = $record.FileReference
                ParentReference = $record.ParentReference
                USN             = $record.Usn
                ReasonDecimal   = $reason
                ReasonHex       = ("0x{0:X8}" -f $reason)
                ReasonsPresent  = $names -join " | "
                RequiredFlags   = "0x00001000 | 0x80000000"
                Indicator       = "MATCH"
            })
        }
    }

    Write-Host "[+] Match fallback: $fallbackMatches" -ForegroundColor Green
}
else {
    Write-Host ""
    Write-Host "[+] Match Explorer primario: $explorerPrimaryMatches" -ForegroundColor Green
    Write-Host "[*] Fallback non necessario." -ForegroundColor DarkGray
}

# ============================================================
# RISULTATI
# ============================================================

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "             ANALISI COMPLETATA" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Record analizzati : $processed" -ForegroundColor Gray
Write-Host "Match totali      : $matches" -ForegroundColor Gray
Write-Host "Explorer primari  : $explorerPrimaryMatches" -ForegroundColor Gray
Write-Host "Explorer fallback: $fallbackMatches" -ForegroundColor Gray
Write-Host ""

if ($findings.Count -eq 0) {
    Write-Host "NESSUN INDICATORE TROVATO" -ForegroundColor Green
}
else {
    Write-Host "INDICATORI TROVATI" -ForegroundColor Yellow
    Write-Host ""

    $findings |
        Sort-Object TimeStamp |
        Format-Table TimeStamp, Technique, Variant, DetectionMode, FileName, ReasonHex -AutoSize -Wrap

    try {
        $findings |
            Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8

        Write-Host ""
        Write-Host "[+] Report salvato:" -ForegroundColor Green
        Write-Host $OutputCsv -ForegroundColor Cyan
    }
    catch {
        Write-Host "[!] Errore salvataggio CSV: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Nota: i match richiedono verifica forense." -ForegroundColor DarkYellow
Write-Host ""
