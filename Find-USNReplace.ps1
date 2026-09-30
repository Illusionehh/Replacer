#requires -RunAsAdministrator

<#
.SYNOPSIS
    USN Journal Replace Detector

.DESCRIPTION
    Analizza il Windows USN Journal alla ricerca di sequenze di eventi
    filesystem potenzialmente compatibili con attività di file replacement.

    Il tool è destinato a finalità di digital forensics e detection.
    Un match NON costituisce, da solo, prova conclusiva di file replacement,
    cheating o altra attività illecita.

.AUTHOR
    illusionehh
#>

param(
    [Parameter(Mandatory = $false)]
    [ValidatePattern("^[A-Za-z]:$")]
    [string]$Drive = "C:",

    [Parameter(Mandatory = $false)]
    [string]$OutputCsv = ".\usn_replace_findings.csv",

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 3600)]
    [int]$MaxGapSeconds = 30
)

$ErrorActionPreference = "Stop"

# ============================================================
# Banner
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
# Prerequisite checks
# ============================================================

if (-not (Get-Command fsutil.exe -ErrorAction SilentlyContinue)) {
    Write-Error "fsutil.exe non è disponibile."
    exit 1
}

if (-not (Test-Path "$Drive\")) {
    Write-Error "L'unità $Drive non è disponibile."
    exit 1
}

Write-Host "[*] Drive              : $Drive" -ForegroundColor Gray
Write-Host "[*] Max event gap      : $MaxGapSeconds seconds" -ForegroundColor Gray
Write-Host "[*] Output             : $OutputCsv" -ForegroundColor Gray
Write-Host ""

# ============================================================
# USN Journal
# ============================================================

Write-Host "[*] Lettura USN Journal..." -ForegroundColor Cyan

try {
    $raw = @(fsutil.exe usn readjournal $Drive csv 2>$null)
}
catch {
    Write-Error "Errore durante la lettura dell'USN Journal: $($_.Exception.Message)"
    exit 1
}

if ($raw.Count -eq 0) {
    Write-Error "Nessun dato restituito dall'USN Journal."
    exit 1
}

Write-Host "[+] Righe ricevute: $($raw.Count)" -ForegroundColor Green

# ============================================================
# CSV parsing
# ============================================================

$events = New-Object System.Collections.Generic.List[object]

foreach ($line in $raw) {

    if ([string]::IsNullOrWhiteSpace($line)) {
        continue
    }

    try {
        $record = $line | ConvertFrom-Csv

        if (-not $record.FileName) {
            continue
        }

        $events.Add(
            [PSCustomObject]@{
                RecordNumber              = $record.RecordNumber
                MajorVersion              = $record.MajorVersion
                MinorVersion              = $record.MinorVersion
                FileReferenceNumber       = $record.FileReferenceNumber
                ParentFileReferenceNumber = $record.ParentFileReferenceNumber
                USN                       = $record.USN
                TimeStamp                 = $record.TimeStamp
                Reason                    = $record.Reason
                SourceInfo                = $record.SourceInfo
                SecurityId                = $record.SecurityId
                FileAttributes            = $record.FileAttributes
                FileName                  = $record.FileName
            }
        )
    }
    catch {
        continue
    }
}

if ($events.Count -eq 0) {
    Write-Error "Non è stato possibile interpretare alcun record."
    exit 1
}

Write-Host "[+] Record interpretati: $($events.Count)" -ForegroundColor Green

# ============================================================
# Reason normalization
# ============================================================

function Get-NormalizedReasons {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Reason
    )

    $result = New-Object System.Collections.Generic.List[string]

    if ([string]::IsNullOrWhiteSpace($Reason)) {
        return $result.ToArray()
    }

    $r = $Reason.ToLowerInvariant()

    if ($r -match "file[_ ]?delete") {
        $result.Add("File Delete")
    }

    if ($r -match "rename[_ ]?old") {
        $result.Add("Rename: old name")
    }

    if ($r -match "rename[_ ]?new") {
        $result.Add("Rename: new name")
    }

    if ($r -match "data[_ ]?extend") {
        $result.Add("Data Extend")
    }

    if ($r -match "data[_ ]?truncation") {
        $result.Add("Data Truncation")
    }

    if ($r -match "data[_ ]?overwrite") {
        $result.Add("Data Overwrite")
    }

    if ($r -match "security[_ ]?change") {
        $result.Add("Security Change")
    }

    if ($r -match "basic[_ ]?info") {
        $result.Add("Basic Info Change")
    }

    if ($r -match "\bclose\b") {
        $result.Add("Close")
    }

    return $result.ToArray()
}

# ============================================================
# Normalize events
# ============================================================

$normalized = New-Object System.Collections.Generic.List[object]

foreach ($event in $events) {

    $reasons = Get-NormalizedReasons -Reason $event.Reason

    foreach ($reason in $reasons) {

        $normalized.Add(
            [PSCustomObject]@{
                FileReference       = $event.FileReferenceNumber
                ParentReference     = $event.ParentFileReferenceNumber
                FileName            = $event.FileName
                TimeStamp           = $event.TimeStamp
                Reason              = $reason
                USN                 = $event.USN
                OriginalReason      = $event.Reason
            }
        )
    }
}

Write-Host "[+] Eventi normalizzati: $($normalized.Count)" -ForegroundColor Green

# ============================================================
# Detection patterns
# ============================================================

$Patterns = [ordered]@{

    "Explorer" = @(
        @("File Delete", "Close"),
        @("Rename: old name", "Rename: new name"),
        @("Rename: new name", "Close")
    )

    "Type 1" = @(
        @("Data Extend", "Data Truncation"),
        @("Data Extend", "Data Truncation", "Close")
    )

    "Type 2" = @(
        @("Data Truncation"),
        @("Data Extend", "Data Truncation")
    )

    "Copy 1" = @(
        @("Data Truncation", "Security Change"),
        @("Data Extend", "Data Truncation", "Security Change"),
        @(
            "Data Overwrite",
            "Data Extend",
            "Data Truncation",
            "Security Change"
        ),
        @(
            "Data Overwrite",
            "Data Extend",
            "Data Truncation",
            "Security Change",
            "Basic Info Change"
        ),
        @(
            "Data Overwrite",
            "Data Extend",
            "Data Truncation",
            "Security Change",
            "Basic Info Change",
            "Close"
        )
    )

    "Copy 2" = @(
        @("Data Truncation"),
        @("Data Extend", "Data Truncation"),
        @(
            "Data Overwrite",
            "Data Extend",
            "Data Truncation"
        ),
        @(
            "Data Overwrite",
            "Data Extend",
            "Data Truncation",
            "Basic Info Change"
        ),
        @(
            "Data Overwrite",
            "Data Extend",
            "Data Truncation",
            "Basic Info Change",
            "Close"
        )
    )

    "HEX 1" = @(
        @("Data Extend"),
        @("Data Overwrite", "Data Extend"),
        @("Data Overwrite", "Data Extend", "Close")
    )

    "HEX 2" = @(
        @("Data Overwrite", "Data Extend"),
        @("Data Overwrite", "Data Extend", "Close")
    )
}

# ============================================================
# Timestamp helper
# ============================================================

function Convert-ToDateTime {

    param(
        [object]$Value
    )

    try {
        return [DateTime]::Parse(
            [string]$Value,
            [Globalization.CultureInfo]::InvariantCulture
        )
    }
    catch {
        return $null
    }
}

# ============================================================
# Pattern matcher
# ============================================================

function Find-Pattern {

    param(
        [Parameter(Mandatory = $true)]
        [array]$Events,

        [Parameter(Mandatory = $true)]
        [array]$Pattern,

        [Parameter(Mandatory = $true)]
        [int]$MaxGap
    )

    if ($Events.Count -lt $Pattern.Count) {
        return $null
    }

    for ($i = 0; $i -le ($Events.Count - $Pattern.Count); $i++) {

        $matched = $true

        for ($j = 0; $j -lt $Pattern.Count; $j++) {

            $current = $Events[$i + $j]

            if ($current.Reason -ne $Pattern[$j]) {
                $matched = $false
                break
            }

            if ($j -gt 0) {

                $previous = $Events[$i + $j - 1]

                $previousTime = Convert-ToDateTime $previous.TimeStamp
                $currentTime  = Convert-ToDateTime $current.TimeStamp

                if ($null -ne $previousTime -and $null -ne $currentTime) {

                    $gap = ($currentTime - $previousTime).TotalSeconds

                    if ($gap -lt 0 -or $gap -gt $MaxGap) {
                        $matched = $false
                        break
                    }
                }
            }
        }

        if ($matched) {
            return @(
                $Events[$i..($i + $Pattern.Count - 1)]
            )
        }
    }

    return $null
}

# ============================================================
# Detection
# ============================================================

Write-Host ""
Write-Host "[*] Analisi delle sequenze..." -ForegroundColor Cyan

$findings = New-Object System.Collections.Generic.List[object]

$groups = $normalized |
    Group-Object FileReference

foreach ($group in $groups) {

    $fileEvents = @(
        $group.Group |
        Sort-Object {
            $date = Convert-ToDateTime $_.TimeStamp

            if ($null -eq $date) {
                [DateTime]::MinValue
            }
            else {
                $date
            }
        }
    )

    foreach ($technique in $Patterns.Keys) {

        foreach ($pattern in $Patterns[$technique]) {

            $hit = Find-Pattern `
                -Events $fileEvents `
                -Pattern $pattern `
                -MaxGap $MaxGapSeconds

            if ($null -ne $hit) {

                $findings.Add(
                    [PSCustomObject]@{
                        DetectionTime   = $hit[0].TimeStamp
                        Technique       = $technique
                        FileName        = $hit[0].FileName
                        FileReference   = $hit[0].FileReference
                        ParentReference = $hit[0].ParentReference
                        Sequence        = ($hit.Reason -join " -> ")
                        EventCount      = $hit.Count
                        USNs            = ($hit.USN -join ", ")
                        Confidence      = "Indicator"
                    }
                )

                break
            }
        }
    }
}

# ============================================================
# Results
# ============================================================

Write-Host ""

if ($findings.Count -eq 0) {

    Write-Host "============================================" -ForegroundColor Green
    Write-Host "  NO MATCHES FOUND" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Nessuna delle sequenze configurate è stata rilevata."

}
else {

    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host "  USN REPLACE INDICATORS DETECTED"
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host ""

    $findings |
        Sort-Object DetectionTime |
        Format-Table `
            DetectionTime,
            Technique,
            FileName,
            Sequence `
            -Wrap `
            -AutoSize

    $findings |
        Export-Csv `
            -Path $OutputCsv `
            -NoTypeInformation `
            -Encoding UTF8

    Write-Host ""
    Write-Host "[!] Indicators found : $($findings.Count)" -ForegroundColor Yellow
    Write-Host "[+] CSV report       : $OutputCsv" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "Analysis completed." -ForegroundColor Cyan
