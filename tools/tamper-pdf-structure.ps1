param(
    [Parameter(Mandatory = $true)]
    [string] $InputPath,

    [string] $OutputPath
)

$source = Resolve-Path -LiteralPath $InputPath

if (-not $OutputPath) {
    $directory = Split-Path -Parent $source.Path
    $name = [System.IO.Path]::GetFileNameWithoutExtension($source.Path)
    $OutputPath = Join-Path $directory "$name-estrutural-adulterado.pdf"
}

$bytes = [System.IO.File]::ReadAllBytes($source.Path)
$latin1 = [System.Text.Encoding]::GetEncoding("ISO-8859-1")
$text = $latin1.GetString($bytes)

if (-not $text.StartsWith("%PDF-")) {
    throw "Arquivo nao parece ser um PDF valido: $($source.Path)"
}

$startMatches = [System.Text.RegularExpressions.Regex]::Matches(
    $text,
    "startxref\s+(\d+)\s+%%EOF",
    [System.Text.RegularExpressions.RegexOptions]::Singleline
)
if ($startMatches.Count -eq 0) {
    throw "Nao foi possivel localizar startxref/%%EOF no PDF."
}

$lastStart = $startMatches[$startMatches.Count - 1]
$previousStartXref = [int64] $lastStart.Groups[1].Value
$prefix = $text.Substring(0, $lastStart.Index)

$trailerMatches = [System.Text.RegularExpressions.Regex]::Matches(
    $prefix,
    "trailer\s*<<(.*?)>>",
    [System.Text.RegularExpressions.RegexOptions]::Singleline
)
if ($trailerMatches.Count -eq 0) {
    throw "PDF com trailer classico nao encontrado. Este script didatico nao manipula xref stream."
}

$trailer = $trailerMatches[$trailerMatches.Count - 1].Groups[1].Value
$sizeMatch = [System.Text.RegularExpressions.Regex]::Match($trailer, "/Size\s+(\d+)")
$rootMatch = [System.Text.RegularExpressions.Regex]::Match($trailer, "/Root\s+(\d+)\s+(\d+)\s+R")
if (-not $sizeMatch.Success -or -not $rootMatch.Success) {
    throw "Trailer PDF sem /Size ou /Root reconhecivel."
}

$newObjectNumber = [int] $sizeMatch.Groups[1].Value
$rootObject = $rootMatch.Groups[1].Value
$rootGeneration = $rootMatch.Groups[2].Value
$timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddHHmmss")
$newObjectOffset = $bytes.Length
$xrefOffset = $newObjectOffset

$idLine = ""
$idMatch = [System.Text.RegularExpressions.Regex]::Match($trailer, "/ID\s*(\[[^\]]+\])", [System.Text.RegularExpressions.RegexOptions]::Singleline)
if ($idMatch.Success) {
    $idLine = "/ID $($idMatch.Groups[1].Value)`n"
}

$encryptLine = ""
$encryptMatch = [System.Text.RegularExpressions.Regex]::Match($trailer, "/Encrypt\s+(\d+)\s+(\d+)\s+R")
if ($encryptMatch.Success) {
    $encryptLine = "/Encrypt $($encryptMatch.Groups[1].Value) $($encryptMatch.Groups[2].Value) R`n"
}

$incrementalUpdate = @"

% demo-adulteracao-estrutural: revisao incremental apos assinatura
$newObjectNumber 0 obj
<<
/Producer (tamper-pdf-structure demo)
/ModDate (D:${timestamp}Z)
/TamperDemo (Structural incremental update after signature)
>>
endobj
xref
$newObjectNumber 1
$($newObjectOffset.ToString("0000000000")) 00000 n 
trailer
<<
/Size $($newObjectNumber + 1)
/Root $rootObject $rootGeneration R
/Info $newObjectNumber 0 R
$idLine$encryptLine/Prev $previousStartXref
>>
startxref
$xrefOffset
%%EOF
"@

$outputBytes = New-Object byte[] ($bytes.Length + $latin1.GetByteCount($incrementalUpdate))
[Array]::Copy($bytes, $outputBytes, $bytes.Length)
$latin1.GetBytes($incrementalUpdate, 0, $incrementalUpdate.Length, $outputBytes, $bytes.Length) | Out-Null
[System.IO.File]::WriteAllBytes($OutputPath, $outputBytes)

Write-Host "PDF com adulteracao estrutural gerado em: $OutputPath"
