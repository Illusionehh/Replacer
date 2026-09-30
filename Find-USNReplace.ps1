#requires -RunAsAdministrator

<#
.SYNOPSIS
    USN Replace Detector v2

.DESCRIPTION
    Analizza il Windows NTFS USN Change Journal alla ricerca
    di combinazioni di USN_REASON flag compatibili con le
    sequenze configurate nel detector.

    Il tool è destinato a finalità di detection e digital forensics.
    Un match è un INDICATORE e non costituisce, da solo,
    una prova conclusiva di file replacement.

.AUTHOR
    illusionehh

.VERSION
    2.0
#>

param(
    [Parameter(Mandatory = $false)]
    [ValidatePattern("^[A-Za-z]:$")]
    [string]$Drive = "C:",

    [Parameter(Mandatory = $false)]
    [string]$OutputCsv = ".\usn_replace_findings.csv"
)

$ErrorActionPreference = "Stop"

# ============================================================
# BANNER
# ============================================================

$Banner = @'
                                         ▄▄▄▀▀▀█
                                          █   █
  ▀▄▄▄▄▄▄▄▀   ▄▀▀█▀▀█▀▄▄     ▀▄▄▄▄▄▄▄▀    █ ░ █    ▄▀▀▒▀▀▄█▄▄▄▄▄
 ██▓██▀██▓█  █ ░▒█  ▒█▓█░   ██▓██▀██▓██   █░▒░█   █ ░ █   ░█▓██
█▓▒▓ ▌ ▐ ▓▒ █▒░▒░   ░▓▀▀▀  █▓▒▓     ▓▒▓█  █▒▓▒█  █░▒░█    █▓▒▓█
█▒░▒▓       █▒▓▒█▀■▀▀▀     █▒░▒▓   ▓▒░▒█  █▓█▓░  █▒▓▒█    █▒░▒░
█░ ░▓       █▓█▓░    ▄▄■▄  █░ ░▓   ▓░ ░█  █ ░ ▒  █▓█▓█    █░ ░▒
██ ░░        █ ░▒▄ ▄▒░░▒▓▌ ██ ░▒ ▄ ▒░ █   █░▒░▓   █▒░▒ ▄ ▄█ ░ ▓
▄▄▀▄▄          ▀▄▄▄▄▀▀▀▀   █░█░■▄■▄▄▄▀    █▀▀▀      ▀▀▀▀▀  ▀■▄█▄
                           █▒█▒█         ▀▀
                           █▓▄▓█
                           ▀▀▀▀▀

                         made by illusionehh
'@

Write-Host $Banner -ForegroundColor Cyan
Write-Host ""

# ============================================================
# USN REASON FLAGS
# Microsoft documented values
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

    # 0x80000000 = 2147483648
    CLOSE                 = [int64]2147483648
}

function Convert-ToReasonInt64 {

    param(
        [Parameter(Mandatory = $true)]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    $text = ([string]$Value).Trim()

    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    try {
        if ($text -match '^0x[0-9a-fA-F]+$') {
            return [int64]([Convert]::ToInt64(
                $text.Substring(2),
                16
            ))
        }

        $value = [int64]$text

        # fsutil può rappresentare 0x80000000 come -2147483648
        if ($value -lt 0) {
            return $value + 4294967296
        }

        return $value
    }
    catch {
        return $null
    }
}

function Test-ReasonMask {

    param(
        [Parameter(Mandatory = $true)]
        [int64]$Reason,

        [Parameter(Mandatory = $true)]
        [int64[]]$RequiredFlags
    )

    $required = [int64]0

    foreach ($flag in $RequiredFlags) {
        $required = $required -bor $flag
    }

    return (($Reason -band $required) -eq $required)
}

function Get-ReasonNames {

    param(
        [Parameter(Mandatory = $true)]
        [int64]$Reason
    )

    $names = New-Object System.Collections.Generic.List[string]

    foreach ($entry in $USN.GetEnumerator()) {

        $flag = [int64]$entry.Value

        if (($Reason -band $flag) -eq $flag) {
            $names.Add($entry.Key)
        }
    }

    return $names.ToArray()
}

# ============================================================
# HELPER: restituisce i flag leggibili
# ============================================================
# ============================================================
# PATTERN
#
# Ogni elemento rappresenta un SINGOLO USN record.
# All'interno del record, tutti i flag indicati devono essere
# presenti contemporaneamente.
# ============================================================

$Patterns = @(

    # --------------------------------------------------------
    # EXPLORER
    # --------------------------------------------------------

    [PSCustomObject]@{
        Technique = "Explorer"
        Variant   = "File Delete + Close"
        Required  = @(
            $USN.FILE_DELETE,
            $USN.CLOSE
        )
    },

    [PSCustomObject]@{
        Technique = "Explorer"
        Variant   = "Rename Old Name"
        Required  = @(
            $USN.RENAME_OLD_NAME
        )
    },

    [PSCustomObject]@{
        Technique = "Explorer"
        Variant   = "Rename New Name"
        Required  = @(
            $USN.RENAME_NEW_NAME
        )
    },

    [PSCustomObject]@{
        Technique = "Explorer"
        Variant   = "Rename New Name + Close"
        Required  = @(
            $USN.RENAME_NEW_NAME,
            $USN.CLOSE
        )
    },

    # --------------------------------------------------------
    # TYPE 1
    # --------------------------------------------------------

    [PSCustomObject]@{
        Technique = "Type 1"
        Variant   = "Data Extend + Data Truncation"
        Required  = @(
            $USN.DATA_EXTEND,
            $USN.DATA_TRUNCATION
        )
    },

    [PSCustomObject]@{
        Technique = "Type 1"
        Variant   = "Data Extend + Data Truncation + Close"
        Required  = @(
            $USN.DATA_EXTEND,
            $USN.DATA_TRUNCATION,
            $USN.CLOSE
        )
    },

    # --------------------------------------------------------
    # TYPE 2
    # --------------------------------------------------------

    [PSCustomObject]@{
        Technique = "Type 2"
        Variant   = "Data Truncation"
        Required  = @(
            $USN.DATA_TRUNCATION
        )
    },

    [PSCustomObject]@{
        Technique = "Type 2"
        Variant   = "Data Extend + Data Truncation"
        Required  = @(
            $USN.DATA_EXTEND,
            $USN.DATA_TRUNCATION
        )
    },

    # --------------------------------------------------------
    # COPY 1
    # --------------------------------------------------------

    [PSCustomObject]@{
        Technique = "Copy 1"
        Variant   = "Data Truncation + Security Change"
        Required  = @(
            $USN.DATA_TRUNCATION,
            $USN.SECURITY_CHANGE
        )
    },

    [PSCustomObject]@{
        Technique = "Copy 1"
        Variant   = "Data Extend + Data Truncation + Security Change"
        Required  = @(
            $USN.DATA_EXTEND,
            $USN.DATA_TRUNCATION,
            $USN.SECURITY_CHANGE
        )
    },

    [PSCustomObject]@{
        Technique = "Copy 1"
        Variant   = "Overwrite + Extend + Truncation + Security"
        Required  = @(
            $USN.DATA_OVERWRITE,
            $USN.DATA_EXTEND,
            $USN.DATA_TRUNCATION,
            $USN.SECURITY_CHANGE
        )
    },

    [PSCustomObject]@{
        Technique = "Copy 1"
        Variant   = "Overwrite + Extend + Truncation + Security + BasicInfo"
        Required  = @(
            $USN.DATA_OVERWRITE,
            $USN.DATA_EXTEND,
            $USN.DATA_TRUNCATION,
            $USN.SECURITY_CHANGE,
            $USN.BASIC_INFO_CHANGE
        )
    },

    [PSCustomObject]@{
        Technique = "Copy 1"
        Variant   = "Overwrite + Extend + Truncation + Security + BasicInfo + Close"
        Required  = @(
            $USN.DATA_OVERWRITE,
            $USN.DATA_EXTEND,
            $USN.DATA_TRUNCATION,
            $USN.SECURITY_CHANGE,
            $USN.BASIC_INFO_CHANGE,
            $USN.CLOSE
        )
    },

    # --------------------------------------------------------
    # COPY 2
    # --------------------------------------------------------

    [PSCustomObject]@{
        Technique = "Copy 2"
        Variant   = "Data Truncation"
        Required  = @(
            $USN.DATA_TRUNCATION
        )
    },

    [PSCustomObject]@{
        Technique = "Copy 2"
        Variant   = "Data Extend + Data Truncation"
        Required  = @(
            $USN.DATA_EXTEND,
            $USN.DATA_TRUNCATION
        )
    },

    [PSCustomObject]@{
        Technique = "Copy 2"
        Variant   = "Overwrite + Extend + Truncation"
        Required  = @(
            $USN.DATA_OVERWRITE,
            $USN.DATA_EXTEND,
            $USN.DATA_TRUNCATION
        )
    },

    [PSCustomObject]@{
        Technique = "Copy 2"
        Variant   = "Overwrite + Extend + Truncation + BasicInfo"
        Required  = @(
            $USN.DATA_OVERWRITE,
            $USN.DATA_EXTEND,
            $USN.DATA_TRUNCATION,
            $USN.BASIC_INFO_CHANGE
        )
    },

    [PSCustomObject]@{
        Technique = "Copy 2"
        Variant   = "Overwrite + Extend + Truncation + BasicInfo + Close"
        Required  = @(
            $USN.DATA_OVERWRITE,
            $USN.DATA_EXTEND,
            $USN.DATA_TRUNCATION,
            $USN.BASIC_INFO_CHANGE,
            $USN.CLOSE
        )
    },

    # --------------------------------------------------------
    # HEX 1
    # --------------------------------------------------------

    [PSCustomObject]@{
        Technique = "HEX 1"
        Variant   = "Data Extend"
        Required  = @(
            $USN.DATA_EXTEND
        )
    },

    [PSCustomObject]@{
        Technique = "HEX 1"
        Variant   = "Data Overwrite + Data Extend"
        Required  = @(
            $USN.DATA_OVERWRITE,
            $USN.DATA_EXTEND
        )
    },

    [PSCustomObject]@{
        Technique = "HEX 1"
        Variant   = "Data Overwrite + Data Extend + Close"
        Required  = @(
            $USN.DATA_OVERWRITE,
            $USN.DATA_EXTEND,
            $USN.CLOSE
        )
    },

    # --------------------------------------------------------
    # HEX 2
    # --------------------------------------------------------

    [PSCustomObject]@{
        Technique = "HEX 2"
        Variant   = "Data Overwrite + Data Extend"
        Required  = @(
            $USN.DATA_OVERWRITE,
            $USN.DATA_EXTEND
        )
    },

    [PSCustomObject]@{
        Technique = "HEX 2"
        Variant   = "Data Overwrite + Data Extend + Close"
        Required  = @(
            $USN.DATA_OVERWRITE,
            $USN.DATA_EXTEND,
            $USN.CLOSE
        )
    }
)

# ============================================================
# CHECK DRIVE
# ============================================================

if (-not (Test-Path "$Drive\")) {
    Write-Host "[!] Drive $Drive non trovata." -ForegroundColor Red
    exit 1
}

if (-not (Get-Command fsutil.exe -ErrorAction SilentlyContinue)) {
    Write-Host "[!] fsutil.exe non disponibile." -ForegroundColor Red
    exit 1
}

Write-Host "[*] Drive   : $Drive" -ForegroundColor Gray
Write-Host "[*] Output  : $OutputCsv" -ForegroundColor Gray
Write-Host ""

# ============================================================
# READ JOURNAL
# ============================================================

Write-Host "[*] Lettura USN Journal..." -ForegroundColor Cyan
Write-Host "[*] Questa operazione può richiedere tempo." -ForegroundColor DarkGray
Write-Host ""

$raw = @(
    & fsutil.exe usn readjournal $Drive csv 2>&1
)

if ($raw.Count -eq 0) {
    Write-Host "[!] Nessun dato restituito da fsutil." -ForegroundColor Red
    exit 1
}

Write-Host "[+] Righe ricevute: $($raw.Count)" -ForegroundColor Green

# ============================================================
# FIND CSV HEADER
# ============================================================
$headerIndex = -1

for ($i = 0; $i -lt $raw.Count; $i++) {

    $line = [string]$raw[$i]

    if (
        $line -match '^(?i)Usn,' -or
        $line -match '^(?i)"?Usn"?,' -or
        $line -match '^(?i)MajorVersion,'
    ) {
        $headerIndex = $i
        break
    }
}

if ($headerIndex -lt 0) {

    Write-Host ""
    Write-Host "[!] Header CSV non trovato." -ForegroundColor Red
    Write-Host ""
    Write-Host "Prime righe restituite da fsutil:" -ForegroundColor Yellow

    $raw |
        Select-Object -First 10 |
        ForEach-Object {
            Write-Host $_
        }

    exit 1
}

Write-Host "[+] CSV header trovato alla riga: $headerIndex" -ForegroundColor Green

# ============================================================
# PARSE CSV
# ============================================================

$csvText = (
    $raw[$headerIndex..($raw.Count - 1)] -join "`r`n"
)

try {
    $records = @(
        $csvText | ConvertFrom-Csv
    )
}
catch {

    Write-Host "[!] Errore durante il parsing CSV:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

if ($records.Count -eq 0) {
    Write-Host "[!] Nessun record CSV interpretato." -ForegroundColor Red
    exit 1
}

Write-Host "[+] Record USN interpretati: $($records.Count)" -ForegroundColor Green
Write-Host ""

# ============================================================
# DETECTION
# ============================================================

$findings = New-Object System.Collections.Generic.List[object]

$processed = 0
$matches   = 0

Write-Host "[*] Analisi Reason bitmask..." -ForegroundColor Cyan

foreach ($record in $records) {

    $processed++

    # Il nome della colonna può essere "Reason".
    $reasonValue = $record.Reason

    $reason = Convert-ToReasonInt64 $reasonValue

    if ($null -eq $reason) {
        continue
    }

    foreach ($pattern in $Patterns) {

        if (
            Test-ReasonMask `
                -Reason $reason `
                -RequiredFlags $pattern.Required
        ) {

            $matches++

            $reasonNames = Get-ReasonNames $reason

            $findings.Add(
                [PSCustomObject]@{
                    TimeStamp       = $record.TimeStamp
                    Technique       = $pattern.Technique
                    Variant         = $pattern.Variant
                    FileName        = $record.FileName
                    FileReference   = $record.FileReferenceNumber
                    ParentReference = $record.ParentFileReferenceNumber
                    USN             = $record.Usn
                    ReasonDecimal   = $reason
                    ReasonHex       = ("0x{0:X8}" -f $reason)
                    ReasonsPresent  = ($reasonNames -join " | ")
                    RequiredFlags   = (
                        $pattern.Required |
                        ForEach-Object {
                            "0x{0:X8}" -f $_
                        }
                    ) -join " | "
                    Indicator       = "MATCH"
                }
            )
        }
    }

    if (($processed % 50000) -eq 0) {
        Write-Host "[*] Processati: $processed / $($records.Count)" -ForegroundColor DarkGray
    }
}

# ============================================================
# RESULTS
# ============================================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "             ANALYSIS COMPLETE" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Record analizzati : $processed" -ForegroundColor Gray
Write-Host "Match trovati     : $matches" -ForegroundColor Gray
Write-Host ""

if ($findings.Count -eq 0) {

    Write-Host "NO MATCHES FOUND" -ForegroundColor Green
    Write-Host ""

}
else {

    Write-Host "INDICATORS DETECTED" -ForegroundColor Yellow
    Write-Host ""

    $findings |
        Sort-Object TimeStamp |
        Format-Table `
            TimeStamp,
            Technique,
            Variant,
            FileName,
            ReasonHex `
            -Wrap `
            -AutoSize

    try {

        $findings |
            Export-Csv `
                -Path $OutputCsv `
                -NoTypeInformation `
                -Encoding UTF8

        Write-Host ""
        Write-Host "[+] Report CSV salvato in:" -ForegroundColor Green
        Write-Host "    $((Resolve-Path $OutputCsv).Path)" -ForegroundColor Cyan
    }
    catch {

        Write-Host ""
        Write-Host "[!] Impossibile creare il CSV: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Nota: un MATCH è un indicatore e richiede verifica forense." -ForegroundColor DarkYellow
Write-Host ""
