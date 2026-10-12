[CmdletBinding()]
param(
    [string]$Drive = $env:SystemDrive,
    [string]$InputFile,
    [string]$OutputCsv,
    [string]$PfCsv,
    [ValidateSet('Exact', 'Contains')][string]$MatchMode = 'Exact',
    [ValidateSet('OEM', 'UTF8')][string]$Encoding = 'OEM',
    [string]$Delimiter = ',',
    [int]$Preview = 10,
    [int]$UsnCol = -1,
    [int]$ReasonCol = -1,
    [int]$NameCol = -1,
    [int]$FileIdCol = -1,
    [int]$TimeCol = -1,
    [int]$AttrCol = -1,
    [string[]]$PriorityExt = @('.exe', '.dll', '.jar', '.py'),
    [string[]]$DeleteExt = @('.exe', '.dll', '.jar', '.ini', '.py'),
    [string[]]$Keywords = @('remote', 'clicker', 'injection', 'bypass', 'macro', 'totem', 'destruct', 'bridge'),
    [string[]]$WatchNames = @('jnativehook'),
    [switch]$Tollerante,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
$swTotal = [Diagnostics.Stopwatch]::StartNew()
$runDate = Get-Date

function Convert-Ext {
    param([string]$Value)
    $x = $Value.Trim().ToLowerInvariant()
    if ($x.Length -gt 0 -and -not $x.StartsWith('.')) { $x = '.' + $x }
    return $x
}

if ($SelfTest) {
    $OutputCsv = Join-Path ([IO.Path]::GetTempPath()) 'Replacer_v5_selftest.csv'
    $PfCsv = $null
}
elseif ([string]::IsNullOrWhiteSpace($OutputCsv)) {
    $here = (Get-Location).Path
    $ans = ''
    try { $ans = Read-Host ("Dove salvo i CSV? Cartella oppure file .csv (Invio = {0})" -f $here) } catch { $ans = '' }
    $ans = ([string]$ans).Trim().Trim('"').Trim("'")
    if ($ans.Length -eq 0) { $ans = $here }
    $ans = [Environment]::ExpandEnvironmentVariables($ans)
    if ($ans.ToLowerInvariant().EndsWith('.csv')) { $OutputCsv = $ans }
    else { $OutputCsv = Join-Path $ans ('Replacer_v5_{0:yyyyMMdd_HHmmss}.csv' -f $runDate) }
}

try {
    $outDir = Split-Path -Path $OutputCsv -Parent
    if ([string]::IsNullOrWhiteSpace($outDir)) {
        $outDir = (Get-Location).Path
        $OutputCsv = Join-Path $outDir $OutputCsv
    }
    if (-not (Test-Path -LiteralPath $outDir)) { [void](New-Item -ItemType Directory -Path $outDir -Force) }
    if ([string]::IsNullOrWhiteSpace($PfCsv)) {
        $PfCsv = Join-Path $outDir ([IO.Path]::GetFileNameWithoutExtension($OutputCsv) + '_pf.csv')
    }
    [IO.File]::WriteAllText($OutputCsv, '')
}
catch {
    throw ("Impossibile usare il percorso di salvataggio '{0}': {1}" -f $OutputCsv, $_.Exception.Message)
}

$osBuild = 0
try { $osBuild = [Environment]::OSVersion.Version.Build } catch { $osBuild = 0 }
$osName = 'non rilevato'
if ($osBuild -ge 22000) { $osName = 'Windows 11' }
elseif ($osBuild -ge 10240) { $osName = 'Windows 10' }

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

$TextMap = @{}
foreach ($e in $flagList) { $TextMap[$e.Key.ToLowerInvariant()] = [long]$e.Value }
$TextMap['extendedattributechange'] = [long]$Flags['EaChange']

$NB_PRI = 1
$NB_PF = 2
$NB_DEL = 4
$NB_KEY = 8
$NB_WATCH = 16

$priSet = @{}
foreach ($e in $PriorityExt) { $priSet[(Convert-Ext $e)] = $true }
$delSet = @{}
foreach ($e in $DeleteExt) { $delSet[(Convert-Ext $e)] = $true }
$kw = @($Keywords | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_.Length -gt 0 })
$wn = @($WatchNames | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_.Length -gt 0 })

function Mask {
    param([string[]]$Names)
    $m = 0L
    foreach ($nm1 in $Names) { $m = $m -bor [long]$Flags[$nm1] }
    return $m
}

function St {
    param(
        [string[]]$Names = @(),
        [string[]]$AnyOf = @(),
        [string]$Mode = '',
        [long[]]$Attrs = $null,
        [int]$NameReq = 0
    )
    return [pscustomobject]@{ Mask = (Mask $Names); Any = (Mask $AnyOf); Mode = $Mode; Attrs = $Attrs; NameReq = $NameReq }
}

$RuleDefs = [ordered]@{
    'Replace'          = @{ Kind = 'Seq'; Steps = @(
            (St 'FileDelete', 'Close'),
            (St 'RenameOldName'),
            (St 'RenameNewName'),
            (St 'RenameNewName', 'Close')) }
    'Type 1'           = @{ Kind = 'Seq'; Steps = @(
            (St 'DataExtend', 'DataTruncation'),
            (St 'DataExtend', 'DataTruncation', 'Close')) }
    'Type 2'           = @{ Kind = 'Seq'; Steps = @(
            (St 'DataTruncation'),
            (St 'DataExtend', 'DataTruncation')) }
    'Copy 1'           = @{ Kind = 'Seq'; Steps = @(
            (St 'DataTruncation', 'SecurityChange'),
            (St 'DataExtend', 'DataTruncation', 'SecurityChange'),
            (St 'DataOverwrite', 'DataExtend', 'DataTruncation', 'SecurityChange'),
            (St 'DataOverwrite', 'DataExtend', 'DataTruncation', 'SecurityChange', 'BasicInfoChange'),
            (St 'DataOverwrite', 'DataExtend', 'DataTruncation', 'SecurityChange', 'BasicInfoChange', 'Close')) }
    'Copy 2'           = @{ Kind = 'Seq'; Steps = @(
            (St 'DataTruncation'),
            (St 'DataExtend', 'DataTruncation'),
            (St 'DataOverwrite', 'DataExtend', 'DataTruncation'),
            (St 'DataOverwrite', 'DataExtend', 'DataTruncation', 'BasicInfoChange'),
            (St 'DataOverwrite', 'DataExtend', 'DataTruncation', 'BasicInfoChange', 'Close')) }
    'HEX 1'            = @{ Kind = 'Seq'; Steps = @(
            (St 'DataExtend'),
            (St 'DataOverwrite', 'DataExtend'),
            (St 'DataOverwrite', 'DataExtend', 'Close')) }
    'HEX 2'            = @{ Kind = 'Seq'; Steps = @(
            (St 'DataOverwrite', 'DataExtend'),
            (St 'DataOverwrite', 'DataExtend', 'Close')) }
    'Eliminazione'     = @{ Kind = 'Flag'; Steps = @(
            (St -Names 'FileDelete' -Mode 'Contains' -NameReq ($NB_DEL -bor $NB_WATCH))) }
    'Rinomina keyword' = @{ Kind = 'Flag'; Steps = @(
            (St -AnyOf 'RenameOldName', 'RenameNewName' -Mode 'Contains' -NameReq $NB_KEY)) }
    'PF sovrascritto'  = @{ Kind = 'Flag'; Steps = @(
            (St -Names 'DataOverwrite' -Mode 'Contains' -NameReq $NB_PF)) }
    'Sola lettura (+)' = @{ Kind = 'Flag'; Steps = @(
            (St -Names 'BasicInfoChange' -Mode 'Exact' -Attrs @(0x21L, 0x2021L) -NameReq $NB_PF)) }
    'Sola lettura (-)' = @{ Kind = 'Flag'; Steps = @(
            (St -Names 'BasicInfoChange' -Mode 'Exact' -Attrs @(0x2020L))) }
    'Icacls'           = @{ Kind = 'Flag'; Steps = @(
            (St -Names 'SecurityChange' -Mode 'Exact' -Attrs @(0x2010L))) }
}

$ruleObjs = New-Object System.Collections.Generic.List[object]
$perRule = [ordered]@{}
$perNear = @{}
$kindOf = @{}
$firstIndex = @{}
$alwaysRules = New-Object System.Collections.Generic.List[object]
$ri = 0
foreach ($rname in $RuleDefs.Keys) {
    $def = $RuleDefs[$rname]
    $steps = [object[]]@($def.Steps)
    $masks = New-Object 'long[]' $steps.Length
    for ($j = 0; $j -lt $steps.Length; $j++) { $masks[$j] = [long]$steps[$j].Mask }
    $ro = [pscustomobject]@{ Index = $ri; Name = $rname; Kind = $def.Kind; Steps = $steps; Masks = $masks; Len = $steps.Length }
    $ruleObjs.Add($ro)
    $perRule[$rname] = 0
    $perNear[$rname] = 0
    $kindOf[$rname] = $def.Kind
    $m0 = $steps[0].Mode
    if (-not $m0) { $m0 = $MatchMode }
    if ($m0 -eq 'Exact') {
        $key0 = [long]$steps[0].Mask
        if (-not $firstIndex.ContainsKey($key0)) { $firstIndex[$key0] = New-Object System.Collections.Generic.List[object] }
        $firstIndex[$key0].Add($ro)
    }
    else { $alwaysRules.Add($ro) }
    $ri++
}

$textCache = @{}
function Get-ReasonText {
    param([long]$Value)
    if ($textCache.ContainsKey($Value)) { return $textCache[$Value] }
    $parts = foreach ($e in $flagList) {
        if (($Value -band [long]$e.Value) -ne 0) { $e.Key -creplace '(?<=[a-z])(?=[A-Z])', ' ' }
    }
    $txt = $parts -join ' | '
    $textCache[$Value] = $txt
    return $txt
}

function Get-NameBits {
    param([string]$FileName)
    $bits = 0
    $ln = $FileName.Trim().ToLowerInvariant()
    $base = $ln
    $isPfName = $ln.EndsWith('.pf')
    if ($isPfName) {
        $bits = $bits -bor $NB_PF
        $base = $ln.Substring(0, $ln.Length - 3)
        $dash = $base.LastIndexOf('-')
        if ($dash -gt 0 -and ($base.Length - $dash - 1) -eq 8) { $base = $base.Substring(0, $dash) }
    }
    $dot = $base.LastIndexOf('.')
    if ($dot -ge 0) {
        $ext = $base.Substring($dot)
        if ($priSet.ContainsKey($ext)) { $bits = $bits -bor $NB_PRI }
        if ((-not $isPfName) -and $delSet.ContainsKey($ext)) { $bits = $bits -bor $NB_DEL }
    }
    foreach ($w in $kw) { if ($ln.Contains($w)) { $bits = $bits -bor $NB_KEY; break } }
    foreach ($w in $wn) { if ($ln.Contains($w)) { $bits = $bits -bor $NB_WATCH; break } }
    return $bits
}

function Test-Step {
    param([int]$Idx, $Step)
    $v = $R[$Idx]
    $mode = $Step.Mode
    if (-not $mode) { $mode = $MatchMode }
    if ($mode -eq 'Exact') { if ($v -ne $Step.Mask) { return $false } }
    else { if (($v -band $Step.Mask) -ne $Step.Mask) { return $false } }
    if ($Step.Any -ne 0 -and (($v -band $Step.Any) -eq 0)) { return $false }
    if ($Step.Attrs) { if ($Step.Attrs -notcontains $A[$Idx]) { return $false } }
    if ($Step.NameReq -ne 0) {
        $bb = $nb[$Idx]
        if ($bb -eq 0) { $bb = (Get-NameBits $NM[$Idx]) -bor 256; $nb[$Idx] = $bb }
        if (($bb -band $Step.NameReq) -eq 0) { return $false }
    }
    return $true
}

function Get-Detail {
    param([string]$Rule, [string]$FileName, [long]$Reason)
    $ln = $FileName.ToLowerInvariant()
    if ($Rule -eq 'Rinomina keyword') {
        $hits = @()
        foreach ($w in $kw) { if ($ln.Contains($w)) { $hits += $w } }
        $side = 'vecchio nome'
        if (($Reason -band 0x2000L) -ne 0) { $side = 'nuovo nome' }
        return ('{0}: {1}' -f $side, ($hits -join '+'))
    }
    if ($Rule -eq 'Eliminazione') {
        foreach ($w in $wn) { if ($ln.Contains($w)) { return ('nome: ' + $w) } }
        $dot = $ln.LastIndexOf('.')
        if ($dot -ge 0) { return ('estensione: ' + $ln.Substring($dot)) }
    }
    return ''
}

function Format-Stamp {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $dt = [datetime]::MinValue
    if ([datetime]::TryParse($Text.Trim(), [ref]$dt)) { return $dt.ToString('yyyy-MM-dd HH:mm:ss') }
    return $Text.Trim()
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
        $hh = $Header[$i]
        if ($hh -match $Pattern -and (-not $Exclude -or $hh -notmatch $Exclude)) { return $i }
    }
    return -1
}

function Esc {
    param([string]$Text)
    return '"' + $Text.Replace('"', '""') + '"'
}

function Show-Preview {
    param($Buckets)
    $titles = @{ 0 = 'FLAG'; 1 = 'Sequenze prioritarie'; 2 = 'Altre sequenze' }
    $colors = @{ 0 = 'Red'; 1 = 'Yellow'; 2 = 'Gray' }
    foreach ($q in 0..2) {
        $lst = $Buckets[$q]
        if ($lst.Count -gt 0) {
            Write-Host ("-- {0} (prime {1})" -f $titles[$q], $lst.Count) -ForegroundColor $colors[$q]
            $lst.ToArray() | Format-Table -AutoSize -Wrap | Out-String -Width 250 | Write-Host
        }
    }
}

$tempToDelete = $null
$expected = $null

if ($SelfTest) {
    $syn = @(
        @(0x00000006L, 'a.exe'),
        @(0x80000006L, 'a.txt'),
        @(0x80000200L, 'b.txt'),
        @(0x00001000L, 'b.txt'),
        @(0x00002000L, 'c.txt'),
        @(0x80002000L, 'c.txt'),
        @(0x00000002L, 'd.txt'),
        @(0x00000100L, 'e.txt'),
        @(0x00000004L, 'd.txt'),
        @(0x00000006L, 'APP.EXE-1A2B3C4D.pf'),
        @(0x00001000L, 'g.txt'),
        @(0x00000002L, 'h.txt'),
        @(0x00000003L, 'h.txt'),
        @(0x80000003L, 'h.txt'),
        @(0x00000100L, 'sep.txt'),
        @(0x80000200L, 'victim.exe'),
        @(0x00000100L, 'sep.txt'),
        @(0x80000200L, 'JNativeHook.dat'),
        @(0x00000100L, 'sep.txt'),
        @(0x80000200L, 'notes.txt'),
        @(0x00000100L, 'sep.txt'),
        @(0x00001000L, 'autoclicker.exe'),
        @(0x00002000L, 'macro_v2.txt'),
        @(0x00002000L, 'harmless.txt'),
        @(0x00000100L, 'sep.txt'),
        @(0x00000003L, 'AB.EXE-1A2B3C4D.pf'),
        @(0x00000100L, 'sep.txt'),
        @(0x00008000L, 'X.EXE-1A2B3C4D.pf', 0x21L),
        @(0x00008000L, 'plain.txt', 0x2020L),
        @(0x00000800L, 'somedir', 0x2010L),
        @(0x00008000L, 'plain2.txt', 0x21L)
    )
    $tempToDelete = [IO.Path]::GetTempFileName()
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('USN,File name,Reason,Time stamp,File attributes,File ID')
    for ($i = 0; $i -lt $syn.Count; $i++) {
        $attrV = 0x20L
        if ($syn[$i].Count -gt 2) { $attrV = $syn[$i][2] }
        $lines.Add(('{0},{1},0x{2:X8}: test,2026-10-01 18:53:{3:00},0x{4:X8},0x{5:X16}' -f (($i + 1) * 100), $syn[$i][1], $syn[$i][0], $i, $attrV, ($i + 1)))
    }
    [IO.File]::WriteAllLines($tempToDelete, $lines, (New-Object System.Text.UTF8Encoding($false)))
    $InputFile = $tempToDelete
    $Encoding = 'UTF8'
    $MatchMode = 'Exact'
    $expected = [ordered]@{
        'Replace' = 1; 'Type 1' = 1; 'Type 2' = 1; 'Copy 1' = 0; 'Copy 2' = 0; 'HEX 1' = 1; 'HEX 2' = 1
        'Eliminazione' = 2; 'Rinomina keyword' = 2; 'PF sovrascritto' = 1
        'Sola lettura (+)' = 1; 'Sola lettura (-)' = 1; 'Icacls' = 1
    }
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

$swRead = [Diagnostics.Stopwatch]::StartNew()
$usnL = New-Object System.Collections.Generic.List[long]
$reaL = New-Object System.Collections.Generic.List[long]
$attL = New-Object System.Collections.Generic.List[long]
$namL = New-Object System.Collections.Generic.List[string]
$fidL = New-Object System.Collections.Generic.List[string]
$tsL = New-Object System.Collections.Generic.List[string]
$rowsRead = 0; $rowsSkipped = 0; $unknownText = 0; $sorted = $true; $lastUsn = [long]::MinValue

$sr = New-Object System.IO.StreamReader($InputFile, $enc, $true)
try {
    $iU = $UsnCol; $iR = $ReasonCol; $iN = $NameCol; $iF = $FileIdCol; $iT = $TimeCol; $iA = $AttrCol
    $headerFound = ($iU -ge 0 -and $iR -ge 0)
    $need = 0

    while ($null -ne ($line = $sr.ReadLine())) {
        if ($line.Length -eq 0) { continue }
        $f = Split-CsvLine $line

        if (-not $headerFound) {
            $hd = [string[]]@($f | ForEach-Object { $_.Trim().ToLowerInvariant() })
            $cu = Find-Col $hd '^usn$'
            $cr = Find-Col $hd 'reason|motiv|caus'
            if ($cu -ge 0 -and $cr -ge 0) {
                $iU = $cu; $iR = $cr
                if ($iN -lt 0) { $iN = Find-Col $hd 'file ?name|nome' }
                if ($iF -lt 0) { $iF = Find-Col $hd '(file ?id|id ?file|id del file)' 'parent|padre|principale|genitore' }
                if ($iT -lt 0) { $iT = Find-Col $hd 'time ?stamp|marca temporale|^data' }
                if ($iA -lt 0) { $iA = Find-Col $hd 'attribut' }
                $headerFound = $true
            }
            continue
        }

        $rowsRead++
        $need = [Math]::Max($iU, $iR) + 1
        if ($f.Length -lt $need) { $rowsSkipped++; continue }

        $us = $f[$iU].Trim()
        $u = 0L
        if ($us.StartsWith('0x')) { try { $u = [Convert]::ToInt64($us.Substring(2), 16) } catch { $rowsSkipped++; continue } }
        elseif (-not [long]::TryParse($us, [ref]$u)) { $rowsSkipped++; continue }

        $rs = $f[$iR]
        $mt = [regex]::Match($rs, '0x([0-9A-Fa-f]{1,8})')
        if ($mt.Success) { $rv = [Convert]::ToInt64($mt.Groups[1].Value, 16) }
        else {
            $rv = 0L
            foreach ($p in $rs.Split('|')) {
                $key = ($p.ToLowerInvariant() -replace '[^a-z]', '')
                if ($key.Length -eq 0) { continue }
                if ($TextMap.ContainsKey($key)) { $rv = $rv -bor $TextMap[$key] } else { $unknownText++ }
            }
        }

        $av = -1L
        if ($iA -ge 0 -and $f.Length -gt $iA) {
            $am = [regex]::Match($f[$iA], '0x([0-9A-Fa-f]{1,8})')
            if ($am.Success) { $av = [Convert]::ToInt64($am.Groups[1].Value, 16) }
            else {
                $tmpv = 0L
                if ([long]::TryParse($f[$iA].Trim(), [ref]$tmpv)) { $av = $tmpv }
            }
        }

        if ($u -lt $lastUsn) { $sorted = $false }
        $lastUsn = $u
        $usnL.Add($u); $reaL.Add($rv); $attL.Add($av)
        $namL.Add($(if ($iN -ge 0 -and $f.Length -gt $iN) { $f[$iN] } else { '' }))
        $fidL.Add($(if ($iF -ge 0 -and $f.Length -gt $iF) { $f[$iF].Trim() } else { '' }))
        $tsL.Add($(if ($iT -ge 0 -and $f.Length -gt $iT) { $f[$iT] } else { '' }))
    }
}
finally {
    $sr.Dispose()
    if ($tempToDelete) { Remove-Item $tempToDelete -ErrorAction SilentlyContinue }
}

if (-not $headerFound) {
    throw "Intestazione non riconosciuta. Indica le colonne a mano con -UsnCol, -ReasonCol, -NameCol, -FileIdCol, -TimeCol, -AttrCol (indici da 0)."
}
$hasAttr = ($iA -ge 0)

$U = $usnL.ToArray(); $R = $reaL.ToArray(); $A = $attL.ToArray()
$NM = $namL.ToArray(); $FID = $fidL.ToArray(); $TS = $tsL.ToArray()
$n = $U.Length

if (-not $sorted -and $n -gt 1) {
    Write-Host 'Record non ordinati per USN: riordino.' -ForegroundColor Yellow
    $keys = [long[]]$U.Clone()
    $ord = [int[]](0..($n - 1))
    [Array]::Sort($keys, $ord)
    $U2 = New-Object 'long[]' $n; $R2 = New-Object 'long[]' $n; $A2 = New-Object 'long[]' $n
    $N2 = New-Object 'string[]' $n; $F2 = New-Object 'string[]' $n; $T2 = New-Object 'string[]' $n
    for ($i = 0; $i -lt $n; $i++) {
        $o = $ord[$i]
        $U2[$i] = $U[$o]; $R2[$i] = $R[$o]; $A2[$i] = $A[$o]
        $N2[$i] = $NM[$o]; $F2[$i] = $FID[$o]; $T2[$i] = $TS[$o]
    }
    $U = $U2; $R = $R2; $A = $A2; $NM = $N2; $FID = $F2; $TS = $T2
}
$swRead.Stop()

$swScan = [Diagnostics.Stopwatch]::StartNew()
$nb = New-Object 'int[]' $n
$mRule = New-Object System.Collections.Generic.List[int]
$mStart = New-Object System.Collections.Generic.List[int]
$mConf = New-Object System.Collections.Generic.List[int]
$exactStarts = @{}
foreach ($ro in $ruleObjs) { $exactStarts[$ro.Index] = New-Object 'System.Collections.Generic.HashSet[int]' }

for ($i = 0; $i -lt $n; $i++) {
    $v = $R[$i]
    for ($pass = 0; $pass -lt 2; $pass++) {
        if ($pass -eq 0) { $cand = $firstIndex[$v] } else { $cand = $alwaysRules }
        foreach ($rule in $cand) {
            $len = $rule.Len
            if (($i + $len) -gt $n) { continue }
            $steps = $rule.Steps
            if ($pass -eq 1) {
                $s0 = $steps[0]
                if (($v -band $s0.Mask) -ne $s0.Mask) { continue }
                if ($s0.Any -ne 0 -and (($v -band $s0.Any) -eq 0)) { continue }
            }
            $ok = $true
            for ($k = 0; $k -lt $len; $k++) {
                if (-not (Test-Step ($i + $k) $steps[$k])) { $ok = $false; break }
            }
            if ($ok) {
                $mRule.Add($rule.Index); $mStart.Add($i); $mConf.Add(0)
                if ($Tollerante) { [void]$exactStarts[$rule.Index].Add($i) }
            }
        }
    }
}

if ($Tollerante -and $MatchMode -eq 'Exact') {
    $seqRules = @($ruleObjs | Where-Object { $_.Kind -eq 'Seq' })
    for ($i = 0; $i -lt $n; $i++) {
        $v = $R[$i]
        foreach ($rule in $seqRules) {
            $masks = $rule.Masks
            if (($v -band $masks[0]) -ne $masks[0]) { continue }
            $len = $rule.Len
            if (($i + $len) -gt $n) { continue }
            $ok = $true
            for ($k = 1; $k -lt $len; $k++) {
                if (($R[$i + $k] -band $masks[$k]) -ne $masks[$k]) { $ok = $false; break }
            }
            if (-not $ok) { continue }
            if ($exactStarts[$rule.Index].Contains($i)) { continue }
            $mRule.Add($rule.Index); $mStart.Add($i); $mConf.Add(1)
        }
    }
}
$swScan.Stop()

$swOut = [Diagnostics.Stopwatch]::StartNew()
$cover = New-Object 'int[]' $n
$cntMain = @(0, 0, 0, 0)
$cntPfR = @(0, 0, 0, 0)
$prevMain = @{}
$prevPf = @{}
foreach ($q in 0..2) {
    $prevMain[$q] = New-Object System.Collections.Generic.List[object]
    $prevPf[$q] = New-Object System.Collections.Generic.List[object]
}
$dateCache = @{}
$prLabels = @('Flag', 'Prioritario', 'Altro')
$csvHeader = (@('MatchId', 'Regola', 'Esito', 'Priorita', 'Passo', 'PassiTotali', 'Data', 'USN', 'MotivoHex', 'Motivo', 'AttributiHex', 'Percorso', 'FileId', 'Dettaglio') -join $Delimiter)
$matchId = 0
$total = $mRule.Count

$sw = New-Object System.IO.StreamWriter($OutputCsv, $false, (New-Object System.Text.UTF8Encoding($true)))
$swPf = $null
try {
    $sw.WriteLine($csvHeader)

    for ($q = 0; $q -lt $total; $q++) {
        $rule = $ruleObjs[$mRule[$q]]
        $i = $mStart[$q]
        $near = ($mConf[$q] -eq 1)
        $len = $rule.Len

        $bAll = 0
        for ($k = 0; $k -lt $len; $k++) {
            $idx = $i + $k
            $bb = $nb[$idx]
            if ($bb -eq 0) { $bb = (Get-NameBits $NM[$idx]) -bor 256; $nb[$idx] = $bb }
            $bAll = $bAll -bor $bb
        }
        $isPf = (($bAll -band $NB_PF) -ne 0)
        if ($rule.Kind -eq 'Flag') { $rank = 0 }
        elseif (($bAll -band $NB_PRI) -ne 0) { $rank = 1 }
        else { $rank = 2 }
        $prLabel = $prLabels[$rank]

        if ($near) { $esito = 'Sequenza parziale'; $rankCount = 3 }
        elseif ($rule.Kind -eq 'Flag') { $esito = 'Flag rilevato'; $rankCount = $rank }
        else { $esito = 'Sequenza rilevata'; $rankCount = $rank }

        if ($isPf) {
            if ($null -eq $swPf) {
                $swPf = New-Object System.IO.StreamWriter($PfCsv, $false, (New-Object System.Text.UTF8Encoding($true)))
                $swPf.WriteLine($csvHeader)
            }
            $out = $swPf
            $cntPfR[$rankCount]++
        }
        else {
            $out = $sw
            $cntMain[$rankCount]++
        }

        $matchId++
        if ($near) { $perNear[$rule.Name]++ } else { $perRule[$rule.Name]++ }

        $firstDs = ''
        $firstDetail = ''
        for ($k = 0; $k -lt $len; $k++) {
            $idx = $i + $k
            $cover[$idx]++
            $raw = $TS[$idx]
            $ds = $dateCache[$raw]
            if ($null -eq $ds) { $ds = Format-Stamp $raw; $dateCache[$raw] = $ds }
            if ($k -eq 0) { $firstDs = $ds }
            $attrTxt = ''
            if ($A[$idx] -ge 0) { $attrTxt = '0x{0:X8}' -f $A[$idx] }
            $detail = ''
            if ($rule.Kind -eq 'Flag') { $detail = Get-Detail $rule.Name $NM[$idx] $R[$idx] }
            if ($k -eq 0) { $firstDetail = $detail }
            $out.WriteLine((@(
                        $matchId, (Esc $rule.Name), (Esc $esito), $prLabel, ($k + 1), $len, $ds, $U[$idx],
                        ('0x{0:X8}' -f $R[$idx]), (Esc (Get-ReasonText $R[$idx])), $attrTxt,
                        (Esc $NM[$idx]), (Esc $FID[$idx]), (Esc $detail)
                    ) -join $Delimiter))
        }

        if (-not $near) {
            if ($isPf) { $tgt = $prevPf[$rank] } else { $tgt = $prevMain[$rank] }
            if ($tgt.Count -lt $Preview) {
                $row = [ordered]@{
                    Id     = $matchId
                    Regola = $rule.Name
                    Data   = $firstDs
                    USN    = (($i..($i + $len - 1)) | ForEach-Object { $U[$_] }) -join ' > '
                    File   = (($i..($i + $len - 1)) | ForEach-Object { $NM[$_] }) -join ' > '
                }
                if ($rank -eq 0) { $row['Dettaglio'] = $firstDetail }
                $tgt.Add([pscustomobject]$row)
            }
        }
    }
}
finally {
    $sw.Dispose()
    if ($null -ne $swPf) { $swPf.Dispose() }
}
$swOut.Stop()

$involved = 0; $overlap = 0
foreach ($c in $cover) { if ($c -gt 0) { $involved++ }; if ($c -gt 1) { $overlap++ } }
$sumMain = $cntMain[0] + $cntMain[1] + $cntMain[2]
$sumPf = $cntPfR[0] + $cntPfR[1] + $cntPfR[2]

Write-Host ''
Write-Host '=== Replacer v5 - riepilogo ===' -ForegroundColor Green
Write-Host ("Data analisi           : {0:yyyy-MM-dd HH:mm:ss}" -f $runDate)
Write-Host ("Sistema                : {0} (build {1})" -f $osName, $osBuild)
Write-Host ("Modalita' di confronto : {0}{1}" -f $MatchMode, $(if ($Tollerante) { ' + tollerante' } else { '' }))
Write-Host ("Righe dati lette       : {0:N0}" -f $rowsRead)
Write-Host ("Record interpretati    : {0:N0}  (scartati: {1:N0})" -f $n, $rowsSkipped)
if ($unknownText -gt 0) { Write-Host ("Descrizioni non riconosciute: {0:N0}" -f $unknownText) -ForegroundColor Yellow }
if (-not $hasAttr) { Write-Host 'Colonna attributi non trovata: disattivati Sola lettura (+/-), Icacls e i filtri sugli attributi (usa -AttrCol).' -ForegroundColor Yellow }
Write-Host ("CSV principale         : {0:N0} rilevamenti  (flag {1:N0}, prioritari {2:N0}, altri {3:N0})" -f $sumMain, $cntMain[0], $cntMain[1], $cntMain[2])
Write-Host ("CSV .pf                : {0:N0} rilevamenti  (flag {1:N0}, prioritari {2:N0}, altri {3:N0})" -f $sumPf, $cntPfR[0], $cntPfR[1], $cntPfR[2])
if ($Tollerante) { Write-Host ("Sequenze parziali      : {0:N0}  (flag in piu' rispetto alla regola)" -f ($cntMain[3] + $cntPfR[3])) -ForegroundColor Yellow }
Write-Host ("Record coinvolti       : {0:N0}  (di cui in piu' rilevamenti: {1:N0})" -f $involved, $overlap)
Write-Host ''
$ruleRows = foreach ($rk in $perRule.Keys) {
    $o = [ordered]@{ Regola = $rk; Tipo = $kindOf[$rk]; Rilevamenti = $perRule[$rk] }
    if ($Tollerante) { $o['Parziali'] = $perNear[$rk] }
    [pscustomobject]$o
}
$ruleRows | Format-Table -AutoSize | Out-String -Width 250 | Write-Host
Write-Host ("Tempi: lettura {0:N1}s, scansione {1:N1}s, scrittura {2:N1}s, totale {3:N1}s" -f $swRead.Elapsed.TotalSeconds, $swScan.Elapsed.TotalSeconds, $swOut.Elapsed.TotalSeconds, $swTotal.Elapsed.TotalSeconds)
Write-Host ("CSV: {0}" -f $OutputCsv)
if ($sumPf + $cntPfR[3] -gt 0) { Write-Host ("CSV .pf: {0}" -f $PfCsv) }

if ($sumMain -gt 0) {
    Write-Host "`nAnteprima CSV principale:" -ForegroundColor Green
    Show-Preview $prevMain
}
if ($sumPf -gt 0) {
    Write-Host "`nAnteprima .pf:" -ForegroundColor Green
    Show-Preview $prevPf
}

if ($osBuild -ge 22000 -and -not $Tollerante) {
    Write-Host "`nWindows 11: se qualche sequenza non viene rilevata, rilancia con -Tollerante (cerca anche sequenze con flag in piu')." -ForegroundColor Yellow
}

if ($SelfTest) {
    $fail = $false
    foreach ($k in $expected.Keys) {
        $got = $perRule[$k]
        $tag = if ($got -eq $expected[$k]) { 'OK  ' } else { $fail = $true; 'FAIL' }
        Write-Host ("[{0}] {1}: atteso {2}, ottenuto {3}" -f $tag, $k, $expected[$k], $got)
    }
    $expMain = @(6, 1, 3)
    $expPf = @(2, 1, 0)
    for ($r2 = 0; $r2 -lt 3; $r2++) {
        $tag = if ($cntMain[$r2] -eq $expMain[$r2]) { 'OK  ' } else { $fail = $true; 'FAIL' }
        Write-Host ("[{0}] CSV principale categoria {1}: atteso {2}, ottenuto {3}" -f $tag, $prLabels[$r2], $expMain[$r2], $cntMain[$r2])
        $tag = if ($cntPfR[$r2] -eq $expPf[$r2]) { 'OK  ' } else { $fail = $true; 'FAIL' }
        Write-Host ("[{0}] CSV .pf categoria {1}: atteso {2}, ottenuto {3}" -f $tag, $prLabels[$r2], $expPf[$r2], $cntPfR[$r2])
    }
    if ($fail) { Write-Host 'SelfTest: FALLITO' -ForegroundColor Red; exit 1 }
    else { Write-Host 'SelfTest: SUPERATO' -ForegroundColor Green }
}
