# Check 7: large files and binaries (port of pr-gate check 7).

$script:FgLargeAssetHelp = "Large or binary assets (models, WASM, packages, archives, executables) don't go in git. Publish them as GitHub Release assets, attached only to releases whose version ends in .0 (vN.N.0), and fetch them from there. Example: talkforge's .github/workflows/release.yml uploads assets/models/*.onnx and assets/vendor/onnx/*.wasm as release assets: https://github.com/fleethacker-data-crucible/talkforge/blob/main/.github/workflows/release.yml"

$script:FgMediaExt = '(?i)\.(png|jpe?g|gif|webp|bmp|ico|icns|svg|avif|tiff?|mp3|wav|ogg|flac|m4a|mp4|webm|mov|woff2?|ttf|otf|eot|pdf)$'
$script:FgOfficeExt = '(?i)\.(docx|xlsx|pptx|odt|ods|odp|epub|doc|xls|ppt)$'

function Get-FgMagicKind {
  # Identifies executables and archives from their first bytes.
  param([byte[]]$Bytes)
  if ($null -eq $Bytes -or $Bytes.Length -lt 2) { return '' }
  $hex = (($Bytes | Select-Object -First 8) | ForEach-Object { $_.ToString('x2') }) -join ''
  if ($hex.StartsWith('4d5a')) { return 'PE executable (MZ)' }
  if ($hex.StartsWith('7f454c46')) { return 'ELF executable' }
  foreach ($m in 'cafebabe', 'cffaedfe', 'cefaedfe', 'feedface', 'feedfacf') { if ($hex.StartsWith($m)) { return 'Mach-O/Java class' } }
  if ($hex.StartsWith('504b0304') -or $hex.StartsWith('504b0506')) { return 'zip archive' }
  if ($hex.StartsWith('1f8b')) { return 'gzip archive' }
  if ($hex.StartsWith('377abcaf271c')) { return '7z archive' }
  if ($hex.StartsWith('0061736d')) { return 'WebAssembly' }
  if ($hex.StartsWith('526172211a07')) { return 'rar archive' }
  if ($hex.StartsWith('d0cf11e0a1b11ae1')) { return 'OLE compound file' }
  return ''
}

function Test-FgBinaryFile {
  # One file's verdict. Status: A (added) or M (modified). Returns a finding or nothing.
  param([string]$Path, [string]$Status, [long]$Size, [byte[]]$Head, [string[]]$BinaryExt, [double]$MaxSizeMB = 5, $Allow)
  $sev = ''; $why = @()
  $limit = [long]($MaxSizeMB * 1MB)
  if ($Size -gt $limit) {
    if ($Status -eq 'A') { $sev = 'FAIL'; $why += "new file over $MaxSizeMB MB" } else { $sev = 'WARN'; $why += "modified file over $MaxSizeMB MB" }
  }
  $ext = [System.IO.Path]::GetExtension($Path).TrimStart('.').ToLowerInvariant()
  $kind = Get-FgMagicKind -Bytes $Head
  $isNul = $false
  if ($Head) { foreach ($b in $Head) { if ($b -eq 0) { $isNul = $true; break } } }
  if ($ext -and ($BinaryExt -contains $ext)) { $sev = 'FAIL'; $why += "archive/binary extension .$ext" }
  elseif ($kind -and ($Path -notmatch $script:FgOfficeExt)) { $sev = 'FAIL'; $why += "$kind by magic bytes" }
  elseif ($kind -or ($Path -match $script:FgOfficeExt)) { if (-not $sev) { $sev = 'WARN' }; $why += 'office document' }
  elseif ($isNul -and ($Path -notmatch $script:FgMediaExt)) { if (-not $sev) { $sev = 'WARN' }; $why += 'binary content (not a known media/font type)' }
  if (-not $sev) { return }
  if ($Allow -and (Test-FgAnyMatch $Path $Allow.path)) {
    if ($sev -eq 'FAIL') { $sev = 'WARN' }
    $why += 'allowlist path (FAIL downgraded)'
  }
  return (New-FgFinding -Check 'binaries' -Kind 'binary' -Severity $sev -Path $Path -Line 0 -Match "$Size bytes" -Note ($why -join '; '))
}

function Find-FgBinaries {
  param([string]$RepoPath, [string]$BaseSha, [string[]]$BinaryExt, [double]$MaxSizeMB = 5, $Allow)
  $out = New-Object System.Collections.Generic.List[object]
  $lines = Invoke-FgGit -RepoPath $RepoPath -GitArgs @('diff', '--no-renames', '--name-status', $BaseSha, 'HEAD')
  foreach ($l in $lines) {
    if (-not $l) { continue }
    $parts = $l -split "`t"
    $st = $parts[0].Substring(0, 1)
    if ($st -ne 'A' -and $st -ne 'M') { continue }
    $p = $parts[$parts.Count - 1]
    $full = [System.IO.Path]::Combine($RepoPath, $p)
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { continue }
    $size = (New-Object System.IO.FileInfo($full)).Length
    $fs = [System.IO.File]::OpenRead($full)
    try { $buf = New-Object byte[] 8192; $n = $fs.Read($buf, 0, 8192) } finally { $fs.Dispose() }
    $head = New-Object byte[] $n; [Array]::Copy($buf, $head, $n)
    $f = Test-FgBinaryFile -Path $p -Status $st -Size $size -Head $head -BinaryExt $BinaryExt -MaxSizeMB $MaxSizeMB -Allow $Allow
    if ($f) { $out.Add($f) }
  }
  return $out
}

function Read-FgBinaryExtensions {
  param([string]$Path)
  $ext = @()
  foreach ($l in [System.IO.File]::ReadAllLines($Path)) {
    if ($l -match '^\s*(#|$)') { continue }
    $ext += ($l -split '\s+' | Where-Object { $_ })
  }
  return $ext
}
