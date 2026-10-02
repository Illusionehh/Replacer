<#
.SYNOPSIS
    Replacer v5 - rilevatore di sequenze CONSECUTIVE di record nel Journal USN.

.DESCRIPTION
    - Legge il journal una sola volta (fsutil usn readjournal <drive> csv, oppure un file gia' salvato).
    - Lavora solo su bitmask numerici (nessun confronto testuale durante la scansione).
    - Scorre i record in ordine USN. Una regola e' una sequenza di record: ogni passo
      della regola e' UN record, e i passi devono essere record adiacenti (nessun record in mezzo).
    - I motivi multipli dentro una riga ("Data Extend | Data Truncation") sono flag dello STESSO record.
    - Gli eventi possono riguardare file diversi: nome file / File ID non vengono mai vincolati.
    - Ogni sequenza trovata viene scritta nel CSV (una riga per record coinvolto) e riassunta in console.

.PARAMETER Drive
    Volume da analizzare (default: unita' di sistema). Servono privilegi di amministratore.

.PARAMETER InputFile
    Usa un file CSV gia' esportato (fsutil usn readjournal X: csv > file) invece di interrogare il volume.

.PARAMETER MatchMode
    Exact    = il record deve avere ESATTAMENTE i flag del passo (default, fedele alle righe elencate).
    Contains = il record deve avere ALMENO i flag del passo.

.PARAMETER PriorityExt
    Estensioni prioritarie: le sequenze che coinvolgono questi file compaiono per prime nell'anteprima a schermo.

.PARAMETER PfCsv
    CSV separato per le sequenze che coinvolgono file .pf (default: <OutputCsv>_pf.csv). Le .pf non vanno nel CSV principale ne' nell'anteprima.

.PARAMETER SelfTest
    Esegue il motore su record sintetici (sequenze valide e da scartare) e verifica i conteggi attesi.

.EXAMPLE
    .\Replacer_v5.ps1 -Drive C:
    .\Replacer_v5.ps1 -InputFile .\usn.csv -MatchMode Contains
    .\Replacer_v5.ps1 -SelfTest
#>
[CmdletBinding()]
param(
    [string]$Drive = $env:SystemDrive,
    [string]$InputFile,
    [string]$OutputCsv = (Join-Path (Get-Location) ("Replacer_v5_{0:yyyyMMdd_HHmmss}.csv" -f (Get-Date))),
    [ValidateSet('Exact', 'Contains')][string]$MatchMode = 'Exact',
    [ValidateSet('OEM', 'UTF8')][string]$Encoding = 'OEM',
    [string]$Delimiter = ';',
    [int]$Preview = 25,
    [int]$UsnCol = -1,
    [int]$ReasonCol = -1,
    [int]$NameCol = -1,
    [int]$FileIdCol = -1,
    [string[]]$PriorityExt = @('.exe', '.dll', '.jar', '.ini', '.py'),
    [string]$PfCsv,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
$swTotal = [Diagnostics.Stopwatch]::StartNew()

# ----------------------------------------------------------------------------
# 1. Flag dei motivi USN (valori numerici ufficiali)
# ----------------------------------------------------------------------------
$Flags = [ordered]@{
    DataOverwrite       = 0x00000001L
    DataExtend          = 0x00000002L
    DataTruncation      = 0x00000004L
    NamedDataOverwrite  = 0x00000010L
    NamedDataExtend     = 0x00000020L
    NamedDataTruncation = 0x00000040L
    FileCreate          = 0x00000100L
    FileDelete          = 0x00000200L
    EaChange            = 0x00000400L
    SecurityChange      = 0x00000800L
    RenameOldName       = 0x00001000L
    RenameNewName       = 0x00002000L
    IndexableChange     = 0x00004000L
    BasicInfoChange     = 0x00008000L
    HardLinkChange      = 0x00010000L
    CompressionChange   = 0x00020000L
    EncryptionChange    = 0x00040000L
    ObjectIdChange      = 0x00080000L
    ReparsePointChange  = 0x00100000L
    StreamChange        = 0x00200000L
    TransactedChange    = 0x00400000L
    IntegrityChange     = 0x00800000L
    Close               = 0x80000000L
}
$flagList = @($Flags.GetEnumerator() | Sort-Object Value)

# Mappa testo -> valore, usata solo come ripiego quando nel CSV manca il valore esadecimale
$TextMap = @{}
foreach ($e in $flagList) { $TextMap[$e.Key.ToLowerInvariant()] = [long]$e.Value }
$TextMap['extendedattributechange'] = [long]$Flags['EaChange']

function Mask {
    param([string[]]$Names)
    $m = 0L
    foreach ($n in $Names) { $m = $m -bor [long]$Flags[$n] }
    return $m
}

# ----------------------------------------------------------------------------
# 2. Regole: ogni voce = sequenza di record consecutivi; ogni elemento = maschera di UN record
# ----------------------------------------------------------------------------
$RuleDefs = [ordered]@{
    'Explorer' = @(
        (Mask 'FileDelete', 'Close'),
        (Mask 'RenameOldName'),
        (Mask 'RenameNewName'),
        (Mask 'RenameNewName', 'Close')
    )
    'Type 1' = @(
        (Mask 'DataExtend', 'DataTruncation'),
        (Mask 'DataExtend', 'DataTruncation', 'Close')
    )
    'Type 2' = @(
        (Mask 'DataTruncation'),
        (Mask 'DataExtend', 'DataTruncation')
    )
    'Copy 1' = @(
        (Mask 'DataTruncation', 'SecurityChange'),
        (Mask 'DataExtend', 'DataTruncation', 'SecurityChange'),
        (Mask 'DataOverwrite', 'DataExtend', 'DataTruncation', 'SecurityChange'),
        (Mask 'DataOverwrite', 'DataExtend', 'DataTruncation', 'SecurityChange', 'BasicInfoChange'),
        (Mask 'DataOverwrite', 'DataExtend', 'DataTruncation', 'SecurityChange', 'BasicInfoChange', 'Close')
    )
    'Copy 2' = @(
        (Mask 'DataTruncation'),
        (Mask 'DataExtend', 'DataTruncation'),
        (Mask 'DataOverwrite', 'DataExtend', 'DataTruncation'),
        (Mask 'DataOverwrite', 'DataExtend', 'DataTruncation', 'BasicInfoChange'),
        (Mask 'DataOverwrite', 'DataExtend', 'DataTruncation', 'BasicInfoChange', 'Close')
    )
    'HEX 1' = @(
        (Mask 'DataExtend'),
        (Mask 'DataOverwrite', 'DataExtend'),
        (Mask 'DataOverwrite', 'DataExtend', 'Close')
    )
    'HEX 2' = @(
        (Mask 'DataOverwrite', 'DataExtend'),
        (Mask 'DataOverwrite', 'DataExtend', 'Close')
    )
}

$ruleObjs = New-Object System.Collections.Generic.List[object]
$perRule = [ordered]@{}
foreach ($name in $RuleDefs.Keys) {
    $masks = [long[]]@($RuleDefs[$name])
    $ruleObjs.Add([pscustomobject]@{ Name = $name; Masks = $masks; Len = $masks.Length })
    $perRule[$name] = 0
}
# Indice sul primo passo: in modalita' Exact evita di provare tutte le regole su ogni record
$firstIndex = @{}
foreach ($r in $ruleObjs) {
    $k = [long]$r.Masks[0]
    if (-not $firstIndex.ContainsKey($k)) { $firstIndex[$k] = New-Object System.Collections.Generic.List[object] }
    $firstIndex[$k].Add($r)
}

# ----------------------------------------------------------------------------
# 3. Utility
# ----------------------------------------------------------------------------
$textCache = @{}
function Get-ReasonText {
    param([long]$Value)
    if ($textCache.ContainsKey($Value)) { return $textCache[$Value] }
    $parts = foreach ($e in $flagList) {
        if (($Value -band [long]$e.Value) -ne 0) { $e.Key -creplace '(?<=[a-z])(?=[A-Z])', ' ' }
    }
    $t = $parts -join ' | '
    $textCache[$Value] = $t
    return $t
}

function Split-CsvLine {
    param([string]$Line)
    if ($Line.IndexOf('"') -lt 0) { return , $Line.Split(',') }
    $res = New-Object System.Collections.Generic.List[string]
    $sb = New-Object System.Text.StringBuilder
    $inQ = $false
    for ($i = 0; $i -lt $Line.Length; $i++) {
        $c = $Line[$i]
        if ($inQ) {
            if ($c -eq '"') {
                if (($i + 1) -lt $Line.Length -and $Line[$i + 1] -eq '"') { [void]$sb.Append('"'); $i++ }
                else { $inQ = $false }
            }
            else { [void]$sb.Append($c) }
        }
        else {
            if ($c -eq '"') { $inQ = $true }
            elseif ($c -eq ',') { $res.Add($sb.ToString()); [void]$sb.Clear() }
            else { [void]$sb.Append($c) }
        }
    }
    $res.Add($sb.ToString())
    return , $res.ToArray()
}

function Find-Col {
    param([string[]]$Header, [string]$Pattern, [string]$Exclude)
    for ($i = 0; $i -lt $Header.Length; $i++) {
        $h = $Header[$i]
        if ($h -match $Pattern -and (-not $Exclude -or $h -notmatch $Exclude)) { return $i }
    }
    return -1
}

function Esc {
    param([string]$s)
    return '"' + $s.Replace('"', '""') + '"'
}

# ----------------------------------------------------------------------------
# 4. Sorgente dati (self-test, file oppure fsutil)
# ----------------------------------------------------------------------------
$tempToDelete = $null
$expected = $null

if ($SelfTest) {
    # Record sintetici: (reason, file). Gli USN sono generati in ordine crescente.
    $syn = @(
        @(0x00000006L, 'a.exe'),    #  1  Ext|Trunc
        @(0x80000006L, 'a.txt'),    #  2  Ext|Trunc|Close            -> Type 1 (1-2)
        @(0x80000200L, 'b.txt'),    #  3  Delete|Close
        @(0x00001000L, 'b.txt'),    #  4  Rename old
        @(0x00002000L, 'c.txt'),    #  5  Rename new  (file diverso)
        @(0x80002000L, 'c.txt'),    #  6  Rename new|Close           -> Explorer (3-6)
        @(0x00000002L, 'd.txt'),    #  7  Extend
        @(0x00000100L, 'e.txt'),    #  8  File create  (interrompe)
        @(0x00000004L, 'd.txt'),    #  9  Trunc                      -> NON deve dare match con 7
        @(0x00000006L, 'f.pf'),     # 10  Ext|Trunc                  -> Type 2 (9-10)
        @(0x00001000L, 'g.txt'),    # 11  Rename old (separatore)
        @(0x00000002L, 'h.txt'),    # 12  Extend
        @(0x00000003L, 'h.txt'),    # 13  Over|Ext
        @(0x80000003L, 'h.txt')     # 14  Over|Ext|Close             -> HEX 1 (12-14), HEX 2 (13-14)
    )
    $tempToDelete = [IO.Path]::GetTempFileName()
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('USN,File name,Reason,Time stamp,File ID')
    for ($i = 0; $i -lt $syn.Count; $i++) {
        $lines.Add(('{0},{1},0x{2:X8}: test,2026-01-01 00:00:00,0x{3:X16}' -f (($i + 1) * 100), $syn[$i][1], $syn[$i][0], ($i + 1)))
    }
    [IO.File]::WriteAllLines($tempToDelete, $lines, (New-Object System.Text.UTF8Encoding($false)))
    $InputFile = $tempToDelete
    $Encoding = 'UTF8'
    $MatchMode = 'Exact'
    $OutputCsv = Join-Path ([IO.Path]::GetTempPath()) 'Replacer_v5_selftest.csv'
    $expected = [ordered]@{ 'Explorer' = 1; 'Type 1' = 1; 'Type 2' = 1; 'Copy 1' = 0; 'Copy 2' = 0; 'HEX 1' = 1; 'HEX 2' = 1 }
    Write-Host 'Modalita'' SelfTest: uso record sintetici.' -ForegroundColor Cyan
}
elseif (-not $InputFile) {
    Write-Host ("Lettura del journal USN di {0} ..." -f $Drive) -ForegroundColor Cyan
    $tempToDelete = [IO.Path]::GetTempFileName()
    cmd /c ('fsutil usn readjournal {0} csv > "{1}"' -f $Drive, $tempToDelete)
    if ($LASTEXITCODE -ne 0 -or (Get-Item $tempToDelete).Length -eq 0) {
        Remove-Item $tempToDelete -ErrorAction SilentlyContinue
        throw "fsutil non ha restituito dati (serve una console avviata come Amministratore, e il journal deve esistere su $Drive)."
    }
    $InputFile = $tempToDelete
}
elseif (-not (Test-Path -LiteralPath $InputFile)) {
    throw "File non trovato: $InputFile"
}

$enc = if ($Encoding -eq 'OEM') {
    [Text.Encoding]::GetEncoding([Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage)
} else { New-Object System.Text.UTF8Encoding($false) }

# ----------------------------------------------------------------------------
# 5. Parsing (una sola lettura, solo valori numerici per la scansione)
# ----------------------------------------------------------------------------
$swRead = [Diagnostics.Stopwatch]::StartNew()
$usnL = New-Object System.Collections.Generic.List[long]
$reaL = New-Object System.Collections.Generic.List[long]
$namL = New-Object System.Collections.Generic.List[string]
$fidL = New-Object System.Collections.Generic.List[string]
$rowsRead = 0; $rowsSkipped = 0; $unknownText = 0; $sorted = $true; $lastUsn = [long]::MinValue

$sr = New-Object System.IO.StreamReader($InputFile, $enc, $true)
try {
    $iU = $UsnCol; $iR = $ReasonCol; $iN = $NameCol; $iF = $FileIdCol
    $headerFound = ($iU -ge 0 -and $iR -ge 0)
    $need = 0

    while ($null -ne ($line = $sr.ReadLine())) {
        if ($line.Length -eq 0) { continue }
        $f = Split-CsvLine $line

        if (-not $headerFound) {
            $h = [string[]]@($f | ForEach-Object { $_.Trim().ToLowerInvariant() })
            $cu = Find-Col $h '^usn$'
            $cr = Find-Col $h 'reason|motiv|caus'
            if ($cu -ge 0 -and $cr -ge 0) {
                $iU = $cu; $iR = $cr
                if ($iN -lt 0) { $iN = Find-Col $h 'file ?name|nome' }
                if ($iF -lt 0) { $iF = Find-Col $h '(file ?id|id ?file|id del file)' 'parent|padre|principale|genitore' }
                $headerFound = $true
            }
            continue
        }

        $rowsRead++
        $need = [Math]::Max($iU, $iR) + 1
        if ($f.Length -lt $need) { $rowsSkipped++; continue }

        # USN
        $us = $f[$iU].Trim()
        $u = 0L
        if ($us.StartsWith('0x')) { try { $u = [Convert]::ToInt64($us.Substring(2), 16) } catch { $rowsSkipped++; continue } }
        elseif (-not [long]::TryParse($us, [ref]$u)) { $rowsSkipped++; continue }

        # Reason: preferisco il valore esadecimale; ripiego sul testo
        $rs = $f[$iR]
        $m = [regex]::Match($rs, '0x([0-9A-Fa-f]{1,8})')
        if ($m.Success) { $rv = [Convert]::ToInt64($m.Groups[1].Value, 16) }
        else {
            $rv = 0L
            foreach ($p in $rs.Split('|')) {
                $key = ($p.ToLowerInvariant() -replace '[^a-z]', '')
                if ($key.Length -eq 0) { continue }
                if ($TextMap.ContainsKey($key)) { $rv = $rv -bor $TextMap[$key] } else { $unknownText++ }
            }
        }

        if ($u -lt $lastUsn) { $sorted = $false }
        $lastUsn = $u
        $usnL.Add($u); $reaL.Add($rv)
        $namL.Add($(if ($iN -ge 0 -and $f.Length -gt $iN) { $f[$iN] } else { '' }))
        $fidL.Add($(if ($iF -ge 0 -and $f.Length -gt $iF) { $f[$iF].Trim() } else { '' }))
    }
}
finally {
    $sr.Dispose()
    if ($tempToDelete) { Remove-Item $tempToDelete -ErrorAction SilentlyContinue }
}

if (-not $headerFound) {
    throw "Intestazione non riconosciuta. Indica le colonne a mano con -UsnCol, -ReasonCol, -NameCol, -FileIdCol (indici da 0)."
}

$U = $usnL.ToArray(); $R = $reaL.ToArray(); $NM = $namL.ToArray(); $FID = $fidL.ToArray()
$n = $U.Length

# L'ordine di riferimento e' l'USN: se il file non e' ordinato lo riordino
if (-not $sorted -and $n -gt 1) {
    Write-Host 'Record non ordinati per USN: riordino.' -ForegroundColor Yellow
    $keys = [long[]]$U.Clone()
    $ord = [int[]](0..($n - 1))
    [Array]::Sort($keys, $ord)
    $U2 = New-Object 'long[]' $n; $R2 = New-Object 'long[]' $n
    $N2 = New-Object 'string[]' $n; $F2 = New-Object 'string[]' $n
    for ($i = 0; $i -lt $n; $i++) { $o = $ord[$i]; $U2[$i] = $U[$o]; $R2[$i] = $R[$o]; $N2[$i] = $NM[$o]; $F2[$i] = $FID[$o] }
    $U = $U2; $R = $R2; $NM = $N2; $FID = $F2
}
$swRead.Stop()

# ----------------------------------------------------------------------------
# 6. Scansione unica in ordine USN
# ----------------------------------------------------------------------------
$swScan = [Diagnostics.Stopwatch]::StartNew()
$exact = ($MatchMode -eq 'Exact')
$cover = New-Object 'int[]' $n
$cls = New-Object 'int[]' $n
for ($i = 0; $i -lt $n; $i++) { $cls[$i] = -1 }

# Classi per estensione: 1 = prioritaria, 2 = prefetch (.pf, CSV separato)
$extClass = @{ '.pf' = 2 }
foreach ($e in $PriorityExt) {
    $x = $e.Trim().ToLowerInvariant()
    if (-not $x.StartsWith('.')) { $x = '.' + $x }
    if ($x -ne '.pf') { $extClass[$x] = 1 }
}
if (-not $PfCsv) {
    $PfCsv = [IO.Path]::Combine((Split-Path $OutputCsv -Parent), ([IO.Path]::GetFileNameWithoutExtension($OutputCsv) + '_pf.csv'))
}

$matchId = 0; $cntPrio = 0; $cntPf = 0; $cntOther = 0
$prioRows = New-Object System.Collections.Generic.List[object]
$otherRows = New-Object System.Collections.Generic.List[object]
$csvHeader = (@('MatchId', 'Regola', 'Passo', 'PassiTotali', 'USN', 'MotivoHex', 'Motivo', 'Percorso', 'FileId', 'Esito', 'Priorita') -join $Delimiter)

$sw = New-Object System.IO.StreamWriter($OutputCsv, $false, (New-Object System.Text.UTF8Encoding($true)))
$swPf = $null
try {
    $sw.WriteLine($csvHeader)

    for ($i = 0; $i -lt $n; $i++) {
        if ($exact) {
            $cand = $firstIndex[$R[$i]]
            if ($null -eq $cand) { continue }
        }
        else { $cand = $ruleObjs }

        foreach ($rule in $cand) {
            $len = $rule.Len
            if (($i + $len) -gt $n) { continue }
            $masks = $rule.Masks
            $ok = $true
            if ($exact) {
                for ($k = 0; $k -lt $len; $k++) { if ($R[$i + $k] -ne $masks[$k]) { $ok = $false; break } }
            }
            else {
                for ($k = 0; $k -lt $len; $k++) { if (($R[$i + $k] -band $masks[$k]) -ne $masks[$k]) { $ok = $false; break } }
            }
            if (-not $ok) { continue }

            $matchId++
            $perRule[$rule.Name]++

            # Classificazione della sequenza: .pf se almeno un record e' .pf, altrimenti
            # prioritaria se almeno un record ha un'estensione prioritaria
            $seqCls = 0
            for ($k = 0; $k -lt $len; $k++) {
                $idx = $i + $k
                $c = $cls[$idx]
                if ($c -lt 0) {
                    $c = 0
                    $nm = $NM[$idx]
                    $d = $nm.LastIndexOf('.')
                    if ($d -ge 0) {
                        $ext = $nm.Substring($d).Trim().ToLowerInvariant()
                        if ($extClass.ContainsKey($ext)) { $c = $extClass[$ext] }
                    }
                    $cls[$idx] = $c
                }
                if ($c -eq 2) { $seqCls = 2 }
                elseif ($c -eq 1 -and $seqCls -eq 0) { $seqCls = 1 }
            }

            if ($seqCls -eq 2) {
                $cntPf++
                if ($null -eq $swPf) {
                    $swPf = New-Object System.IO.StreamWriter($PfCsv, $false, (New-Object System.Text.UTF8Encoding($true)))
                    $swPf.WriteLine($csvHeader)
                }
                $out = $swPf; $label = 'Prefetch (.pf)'
            }
            elseif ($seqCls -eq 1) { $cntPrio++; $out = $sw; $label = 'Prioritario' }
            else { $cntOther++; $out = $sw; $label = 'Altro' }

            for ($k = 0; $k -lt $len; $k++) {
                $idx = $i + $k
                $cover[$idx]++
                $out.WriteLine((@(
                            $matchId, (Esc $rule.Name), ($k + 1), $len, $U[$idx],
                            ('0x{0:X8}' -f $R[$idx]), (Esc (Get-ReasonText $R[$idx])),
                            (Esc $NM[$idx]), (Esc $FID[$idx]), 'Sequenza rilevata', $label
                        ) -join $Delimiter))
            }

            # Anteprima a schermo: le .pf non compaiono, le prioritarie hanno la precedenza
            if ($seqCls -ne 2) {
                $target = if ($seqCls -eq 1) { $prioRows } else { $otherRows }
                if ($target.Count -lt $Preview) {
                    $target.Add([pscustomobject]@{
                            Id     = $matchId
                            Regola = $rule.Name
                            Tipo   = $label
                            USN    = (($i..($i + $len - 1)) | ForEach-Object { $U[$_] }) -join ' > '
                            File   = (($i..($i + $len - 1)) | ForEach-Object { $NM[$_] }) -join ' > '
                        })
                }
            }
        }
    }
}
finally {
    $sw.Dispose()
    if ($null -ne $swPf) { $swPf.Dispose() }
}
$previewRows = New-Object System.Collections.Generic.List[object]
foreach ($r in $prioRows) { $previewRows.Add($r) }
foreach ($r in $otherRows) { if ($previewRows.Count -lt $Preview) { $previewRows.Add($r) } }
$swScan.Stop()

# ----------------------------------------------------------------------------
# 7. Report
# ----------------------------------------------------------------------------
$involved = 0; $overlap = 0
foreach ($c in $cover) { if ($c -gt 0) { $involved++ }; if ($c -gt 1) { $overlap++ } }

Write-Host ''
Write-Host '=== Replacer v5 - riepilogo ===' -
