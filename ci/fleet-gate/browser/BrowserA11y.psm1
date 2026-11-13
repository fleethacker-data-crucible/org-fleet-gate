# fleet-gate browser accessibility scan: axe-core plus computed contrast in a real page.
# Windows PowerShell 5.1; drives the installed Edge or Chrome over the DevTools protocol.
# No Node, nothing installed: axe-core is a pinned, SHA256-checked download into the job's
# temp folder, and pages are served by a loopback-only listener.
# MIT license. ASCII only.

# The six org members whose PRs may run this job on the elevated runner. The reusable
# workflow's job-level if: carries the same list; tests/BrowserGuard.Tests.ps1 checks they match.
$script:FgTeam = @('agathokakological', 'BenKenBoy', 'cyprionceo', 'nullusperfectus', 'seakintruth', 'sun-of-anton')

$script:FgAxe = @{
  Version = '4.14.0'
  Url     = 'https://registry.npmjs.org/axe-core/-/axe-core-4.14.0.tgz'
  Sha256  = '2277b0a3ef47af9b52497faa3e71598e86e0a0e5e6eb295207a5657ede4709af'
  JsSha256 = '20c09fe157a8a34a30e241aaa1fcdade657734f08ab379ecfbeb7d45cc46e878'
}

function Get-FgTeam { return $script:FgTeam }

function Test-FgBrowserScanAllowed {
  # Mirrors the workflow guard: the PR author is one of the six AND the head is the base
  # repo itself or a fork owned by that same author.
  param([string]$EventName, [string]$Author, [string]$HeadRepo, [string]$BaseRepo, [string]$HeadOwner)
  if ($EventName -ne 'pull_request') { return [pscustomobject]@{ Allowed = $false; Reason = "event '$EventName' is not pull_request" } }
  $inTeam = $false
  foreach ($m in $script:FgTeam) { if ($m -ieq $Author) { $inTeam = $true } }
  if (-not $inTeam) { return [pscustomobject]@{ Allowed = $false; Reason = "PR author '$Author' is not on the team list" } }
  if ($HeadRepo -and $BaseRepo -and $HeadRepo -ieq $BaseRepo) { return [pscustomobject]@{ Allowed = $true; Reason = 'team member, same-repo branch' } }
  if ($HeadOwner -and $HeadOwner -ieq $Author) { return [pscustomobject]@{ Allowed = $true; Reason = "team member, from the author's own fork" } }
  return [pscustomobject]@{ Allowed = $false; Reason = "head repo '$HeadRepo' is neither this repo nor a fork owned by '$Author'" }
}

function Get-FgWorkflowGuardLogins {
  # Reads the team list out of a workflow's fromJSON('[...]') guard (for the tests).
  param([string]$WorkflowText)
  $m = [regex]::Match($WorkflowText, "fromJSON\('(\[[^\]]*\])'\)")
  if (-not $m.Success) { return @() }
  return @((ConvertFrom-Json $m.Groups[1].Value))
}

function Install-FgAxe {
  param([string]$Dest)
  if (-not (Test-Path -LiteralPath $Dest)) { $null = New-Item -ItemType Directory -Path $Dest -Force }
  $tgz = [System.IO.Path]::Combine($Dest, 'axe-core.tgz')
  if (-not (Test-Path -LiteralPath $tgz)) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $pp = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'
    try { Invoke-WebRequest -Uri $script:FgAxe.Url -OutFile $tgz -UseBasicParsing } finally { $ProgressPreference = $pp }
  }
  $h = (Get-FileHash -LiteralPath $tgz -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($h -ne $script:FgAxe.Sha256) { Remove-Item -LiteralPath $tgz -Force; throw "axe-core SHA256 mismatch (got $h). Not using it." }
  $dir = [System.IO.Path]::Combine($Dest, 'axe'); $null = New-Item -ItemType Directory -Path $dir -Force
  $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  try { & tar -xzf $tgz -C $dir package/axe.min.js 2>$null } finally { $ErrorActionPreference = $old }
  $js = [System.IO.Path]::Combine($dir, 'package', 'axe.min.js')
  if (-not (Test-Path -LiteralPath $js)) { throw 'axe.min.js not found in the axe-core package' }
  $jh = (Get-FileHash -LiteralPath $js -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($jh -ne $script:FgAxe.JsSha256) { throw "axe.min.js SHA256 mismatch (got $jh)" }
  return $js
}

function Get-FgMimeType {
  param([string]$Path)
  switch -regex ([System.IO.Path]::GetExtension($Path).ToLowerInvariant()) {
    '^\.html?$' { return 'text/html; charset=utf-8' }
    '^\.css$' { return 'text/css; charset=utf-8' }
    '^\.m?js$' { return 'text/javascript; charset=utf-8' }
    '^\.json$' { return 'application/json' }
    '^\.svg$' { return 'image/svg+xml' }
    '^\.png$' { return 'image/png' }
    '^\.jpe?g$' { return 'image/jpeg' }
    '^\.gif$' { return 'image/gif' }
    '^\.webp$' { return 'image/webp' }
    '^\.ico$' { return 'image/x-icon' }
    '^\.woff2$' { return 'font/woff2' }
    '^\.woff$' { return 'font/woff' }
    '^\.ttf$' { return 'font/ttf' }
    '^\.wasm$' { return 'application/wasm' }
    default { return 'application/octet-stream' }
  }
}

function Resolve-FgServePath {
  # Maps a request path onto a file under Root; $null if outside Root or missing.
  param([string]$Root, [string]$UrlPath)
  $p = [Uri]::UnescapeDataString(($UrlPath -split '\?')[0])
  if ($p.EndsWith('/')) { $p += 'index.html' }
  $rel = $p.TrimStart('/').Replace('/', [System.IO.Path]::DirectorySeparatorChar)
  $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
  $full = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($rootFull, $rel))
  if (-not $full.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) { return $null }
  if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { return $null }
  # Refuse symlinks / junctions anywhere between Root and the file.
  $walk = $full
  while ($walk.Length -ge $rootFull.Length) {
    $it = Get-Item -LiteralPath $walk -Force -ErrorAction SilentlyContinue
    if ($null -eq $it -or ($it.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) { return $null }
    $walk = [System.IO.Path]::GetDirectoryName($walk)
    if (-not $walk) { break }
  }
  return $full
}

function Resolve-FgRepoFile {
  # Validates one repo-relative path. Returns @{ Path = <normalized rel>; Full = <full>; Reason = $null }
  # or Reason set when the entry is rooted, escapes RepoPath, is missing, or crosses a reparse point.
  param([string]$RepoPath, [string]$Rel)
  $r = [pscustomobject]@{ Entry = $Rel; Path = $null; Full = $null; Reason = $null }
  $e = ('' + $Rel).Trim()
  if (-not $e) { $r.Reason = 'empty'; return $r }
  if ($e.Contains(':') -or $e -match '^[\\/]' -or [System.IO.Path]::IsPathRooted($e)) { $r.Reason = 'rooted or absolute path'; return $r }
  $sep = [System.IO.Path]::DirectorySeparatorChar
  $relNative = $e.Replace([char]92, $sep).Replace([char]47, $sep)
  $rootFull = [System.IO.Path]::GetFullPath($RepoPath).TrimEnd([char]92, [char]47) + $sep
  $full = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($rootFull, $relNative))
  if (-not $full.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) { $r.Reason = 'resolves outside the repo'; return $r }
  if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { $r.Reason = 'not a file in the repo'; return $r }
  $walk = $full
  while ($walk.Length -ge $rootFull.Length) {
    $it = Get-Item -LiteralPath $walk -Force -ErrorAction SilentlyContinue
    if ($null -eq $it) { $r.Reason = 'not a file in the repo'; return $r }
    if ($it.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { $r.Reason = 'symlink or junction'; return $r }
    $walk = [System.IO.Path]::GetDirectoryName($walk)
    if (-not $walk) { break }
  }
  $r.Full = $full
  $r.Path = $full.Substring($rootFull.Length).Replace($sep, [char]47)
  return $r
}

function Start-FgStaticServer {
  # Serves Root on http://127.0.0.1:<port>/ (loopback only) from a background runspace.
  # The port stays fixed for the whole scan (the browser's proxy bypass names it); set
  # $server.State.Root to serve a different directory.
  param([string]$Root)
  $state = [hashtable]::Synchronized(@{ Root = $Root })
  $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
  $listener.Start()
  $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
  $ps = [PowerShell]::Create()
  $null = $ps.AddScript({
    param($listener, $state, $resolveDef, $mimeDef, $port)
    # Definitions arrive as text: script blocks are bound to their home runspace.
    Set-Item -Path function:Resolve-FgServePath -Value ([ScriptBlock]::Create($resolveDef))
    Set-Item -Path function:Get-FgMimeType -Value ([ScriptBlock]::Create($mimeDef))
    while ($true) {
      try { $client = $listener.AcceptTcpClient() } catch { break }
      try {
        $client.ReceiveTimeout = 5000
        $stream = $client.GetStream()
        $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::ASCII, $false, 4096, $true)
        $req = $reader.ReadLine(); $hostHdr = ''
        while ($true) { $h = $reader.ReadLine(); if ([string]::IsNullOrEmpty($h)) { break }; if ($h -match '^(?i)host:\s*(.+)$') { $hostHdr = $Matches[1].Trim() } }
        $status = '404 Not Found'; $body = [System.Text.Encoding]::UTF8.GetBytes('not found'); $type = 'text/plain'
        if ($hostHdr -ne "127.0.0.1:$port" -and $hostHdr -ne "localhost:$port") { $status = '403 Forbidden'; $body = [System.Text.Encoding]::UTF8.GetBytes('bad host') }
        elseif ($req -match '^GET (\S+) HTTP/1\.[01]$') {
          $f = Resolve-FgServePath -Root $state.Root -UrlPath $Matches[1]
          if ($f) { $status = '200 OK'; $body = [System.IO.File]::ReadAllBytes($f); $type = Get-FgMimeType $f }
        } else { $status = '405 Method Not Allowed'; $body = [System.Text.Encoding]::UTF8.GetBytes('GET only') }
        $hdr = "HTTP/1.1 $status`r`nContent-Type: $type`r`nContent-Length: $($body.Length)`r`nCache-Control: no-store`r`nConnection: close`r`n`r`n"
        $hb = [System.Text.Encoding]::ASCII.GetBytes($hdr)
        $stream.Write($hb, 0, $hb.Length); $stream.Write($body, 0, $body.Length); $stream.Flush()
      } catch { } finally { $client.Close() }
    }
  }).AddArgument($listener).AddArgument($state).AddArgument(${function:Resolve-FgServePath}.ToString()).AddArgument(${function:Get-FgMimeType}.ToString()).AddArgument($port)
  $handle = $ps.BeginInvoke()
  return [pscustomobject]@{ Port = $port; Listener = $listener; PowerShell = $ps; Handle = $handle; State = $state }
}

function Stop-FgStaticServer {
  param($Server)
  if (-not $Server) { return }
  try { $Server.Listener.Stop() } catch { }
  try { $null = $Server.Handle.AsyncWaitHandle.WaitOne(3000); $Server.PowerShell.Dispose() } catch { }
}

function Find-FgBrowser {
  $c = @()
  foreach ($base in @(${env:ProgramFiles(x86)}, $env:ProgramFiles, $env:LOCALAPPDATA)) {
    if (-not $base) { continue }
    $c += [System.IO.Path]::Combine($base, 'Microsoft', 'Edge', 'Application', 'msedge.exe')
    $c += [System.IO.Path]::Combine($base, 'Google', 'Chrome', 'Application', 'chrome.exe')
  }
  $c += '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/microsoft-edge'   # box dry runs only
  foreach ($p in $c) { if (Test-Path -LiteralPath $p) { return $p } }
  throw 'No Edge or Chrome found'
}

function Get-FgBrowserArgs {
  # Launch arguments for the scan browser. All traffic goes to a dead proxy (127.0.0.1:9, discard)
  # and <-loopback> removes the implicit loopback bypass, so the only origin the page can reach is
  # the scan server at 127.0.0.1:ServerPort. Name resolution is disabled except for 127.0.0.1.
  param([string]$ProfileDir, [int]$ServerPort, [switch]$NoSandbox)
  if ($ServerPort -lt 1 -or $ServerPort -gt 65535) { throw 'ServerPort is required' }
  $bargs = @('--headless=new', '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0', "--user-data-dir=$ProfileDir",
    '--proxy-server=127.0.0.1:9', "--proxy-bypass-list=<-loopback>;127.0.0.1:$ServerPort",
    '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1',
    '--force-webrtc-ip-handling-policy=disable_non_proxied_udp', '--disable-quic',
    '--no-first-run', '--no-default-browser-check', '--disable-extensions', '--disable-sync', '--disable-background-networking',
    '--disable-component-update', '--disable-domain-reliability', '--no-pings', '--window-size=1280,900', 'about:blank')
  if ($NoSandbox) { $bargs = @('--no-sandbox') + $bargs }
  return $bargs
}

function Start-FgBrowser {
  # Starts a throwaway headless browser profile with DevTools on a random loopback port.
  param([string]$BrowserPath, [string]$ProfileDir, [int]$ServerPort)
  $null = New-Item -ItemType Directory -Path $ProfileDir -Force
  $noSb = ($PSVersionTable.PSVersion.Major -gt 5 -and -not (Get-Variable -Name IsWindows -ValueOnly -ErrorAction SilentlyContinue))
  $bargs = @(Get-FgBrowserArgs -ProfileDir $ProfileDir -ServerPort $ServerPort -NoSandbox:$noSb)
  # Start-Process joins arguments with spaces; quote the ones that contain spaces.
  $bargs = @($bargs | ForEach-Object { if ($_ -match ' ') { '"' + $_ + '"' } else { $_ } })
  $logBase = $ProfileDir.TrimEnd([char]92, [char]47)
  $portFile = [System.IO.Path]::Combine($ProfileDir, 'DevToolsActivePort')
  # A file left by an earlier run would point at a dead port.
  if (Test-Path -LiteralPath $portFile) { Remove-Item -LiteralPath $portFile -Force }
  $proc = Start-Process -FilePath $BrowserPath -ArgumentList $bargs -PassThru -RedirectStandardError ($logBase + "-stderr.log") -RedirectStandardOutput ($logBase + "-stdout.log")
  $deadline = (Get-Date).AddSeconds(30)
  while (-not (Test-Path -LiteralPath $portFile)) { if ((Get-Date) -gt $deadline) { throw 'browser did not open DevTools' }; Start-Sleep -Milliseconds 200 }
  $port = ''
  while (-not $port) { $l = @(Get-Content -LiteralPath $portFile -ErrorAction SilentlyContinue); if ($l.Count -ge 1) { $port = $l[0].Trim() }; Start-Sleep -Milliseconds 100 }
  $ws = $null; $deadline = (Get-Date).AddSeconds(15)
  while (-not $ws) {
    try {
      $list = Invoke-RestMethod -Uri "http://127.0.0.1:$port/json/list" -UseBasicParsing
      foreach ($t in @($list)) { if ($t.type -eq 'page') { $ws = $t.webSocketDebuggerUrl; break } }
    } catch { }
    if (-not $ws) { if ((Get-Date) -gt $deadline) { throw 'no page target' }; Start-Sleep -Milliseconds 200 }
  }
  return [pscustomobject]@{ Process = $proc; Port = $port; PageWs = $ws; ProfileDir = $ProfileDir }
}

function Connect-FgCdp {
  param([string]$WsUrl)
  $ws = New-Object System.Net.WebSockets.ClientWebSocket
  $ws.Options.KeepAliveInterval = [TimeSpan]::FromSeconds(30)
  $null = $ws.ConnectAsync([Uri]$WsUrl, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
  return [pscustomobject]@{ Socket = $ws; NextId = 1 }
}

function Invoke-FgCdp {
  # Sends one DevTools command and waits for its reply (events are skipped).
  param($Cdp, [string]$Method, [hashtable]$Params = @{}, [int]$TimeoutSec = 60)
  $id = $Cdp.NextId; $Cdp.NextId++
  $msg = @{ id = $id; method = $Method; params = $Params } | ConvertTo-Json -Depth 10 -Compress
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($msg)
  $seg = New-Object System.ArraySegment[byte] -ArgumentList @(, $bytes)
  $null = $Cdp.Socket.SendAsync($seg, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  $buf = New-Object byte[] 65536
  while ((Get-Date) -lt $deadline) {
    $ms = New-Object System.IO.MemoryStream
    do {
      $rs = New-Object System.ArraySegment[byte] -ArgumentList @(, $buf)
      $cts = New-Object Threading.CancellationTokenSource([TimeSpan]::FromSeconds($TimeoutSec))
      $r = $Cdp.Socket.ReceiveAsync($rs, $cts.Token).GetAwaiter().GetResult()
      $ms.Write($buf, 0, $r.Count)
    } while (-not $r.EndOfMessage)
    $text = [System.Text.Encoding]::UTF8.GetString($ms.ToArray())
    $obj = ConvertFrom-Json $text
    if ($obj.id -eq $id) {
      if ($obj.error) { throw "CDP $Method failed: $($obj.error.message)" }
      return $obj.result
    }
  }
  throw "CDP $Method timed out"
}

function Invoke-FgEval {
  param($Cdp, [string]$Expression, [int]$TimeoutSec = 60)
  $r = Invoke-FgCdp -Cdp $Cdp -Method 'Runtime.evaluate' -Params @{ expression = $Expression; awaitPromise = $true; returnByValue = $true } -TimeoutSec $TimeoutSec
  if ($r.exceptionDetails) { throw "page script error: $($r.exceptionDetails.text) $($r.exceptionDetails.exception.description)" }
  return $r.result.value
}

# Computed contrast in the live page: each visible text element's color against its
# effective background (ancestors composited); unknown when a background image is in the way.
$script:FgComputedContrastJs = @'
(() => {
  const parse = s => { const m = s.match(/rgba?\(([^)]+)\)/); if (!m) return null; const p = m[1].split(/[\s,\/]+/).filter(Boolean).map(Number); return [p[0], p[1], p[2], p.length > 3 ? p[3] : 1]; };
  const lum = c => { const f = v => { v /= 255; return v <= 0.04045 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2]); };
  const mix = (t, u) => [t[0] * t[3] + u[0] * (1 - t[3]), t[1] * t[3] + u[1] * (1 - t[3]), t[2] * t[3] + u[2] * (1 - t[3]), 1];
  const bgOf = el => { const layers = []; for (let e = el; e; e = e.parentElement) { const cs = getComputedStyle(e); if (cs.backgroundImage && cs.backgroundImage !== 'none') return null; const c = parse(cs.backgroundColor); if (c && c[3] > 0) { layers.push(c); if (c[3] >= 1) break; } } let b = [255, 255, 255, 1]; for (let i = layers.length - 1; i >= 0; i--) b = mix(layers[i], b); return b; };
  const hex = c => '#' + c.slice(0, 3).map(v => Math.round(v).toString(16).padStart(2, '0')).join('');
  const sel = e => { let s = e.tagName.toLowerCase(); if (e.id) s += '#' + e.id; if (e.classList.length) s += '.' + Array.from(e.classList).join('.'); const p = e.parentElement; return (p && p !== document.body ? (p.tagName.toLowerCase() + (p.classList.length ? '.' + p.classList[0] : '') + ' > ') : '') + s; };
  const out = []; const seen = new Set();
  for (const el of document.body.querySelectorAll('*')) {
    if (!Array.from(el.childNodes).some(n => n.nodeType === 3 && n.textContent.trim())) continue;
    const cs = getComputedStyle(el); const r = el.getBoundingClientRect();
    if (cs.visibility === 'hidden' || cs.display === 'none' || r.width === 0 || r.height === 0 || el.closest('[hidden],[aria-hidden="true"]')) continue;
    if (el.matches(':disabled,[aria-disabled="true"]')) continue;
    const fgc = parse(cs.color); const bg = bgOf(el); if (!fgc || !bg) continue;
    const fg = fgc[3] < 1 ? mix(fgc, bg) : fgc;
    const a = lum(fg), b = lum(bg); const ratio = (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
    const px = parseFloat(cs.fontSize); const bold = parseInt(cs.fontWeight, 10) >= 700;
    const min = (px >= 24 || (bold && px >= 18.66)) ? 3 : 4.5;
    if (ratio < min) { const k = sel(el) + hex(fg) + hex(bg); if (seen.has(k)) continue; seen.add(k); out.push({ selector: sel(el), text: el.textContent.trim().slice(0, 40), fg: hex(fg), bg: hex(bg), ratio: Math.round(ratio * 100) / 100, min }); }
  }
  return JSON.stringify(out.slice(0, 100));
})()
'@

$script:FgAxeRunJs = @'
axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'] }, resultTypes: ['violations'] })
  .then(r => JSON.stringify(r.violations.map(v => ({ id: v.id, impact: v.impact, help: v.help, nodes: v.nodes.slice(0, 10).map(n => ({ target: n.target.join(' '), summary: (n.failureSummary || '').split('\n').slice(0, 2).join(' ') })) }))))
'@

function Get-FgPageList {
  # Pages to scan: .fleet-gate/pages.txt (one repo path per line) or tracked *.html files.
  param([string]$RepoPath, [int]$Max = 15)
  $cfg = [System.IO.Path]::Combine($RepoPath, '.fleet-gate', 'pages.txt')
  $pages = @()
  if (Test-Path -LiteralPath $cfg) {
    $pages = @([System.IO.File]::ReadAllLines($cfg) | Where-Object { $_ -and $_ -notmatch '^\s*#' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
  } else {
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { $all = @(& git -C $RepoPath ls-files 2>$null) } finally { $ErrorActionPreference = $old }
    $pages = @($all | Where-Object { $_ -match '(?i)\.html?$' -and $_ -notmatch '(?i)(?:^|/)(?:node_modules|vendor|tests?|fixtures?|docs|examples?|dist)/' })
  }
  $ok = New-Object System.Collections.Generic.List[string]
  foreach ($p in $pages) {
    $v = Resolve-FgRepoFile -RepoPath $RepoPath -Rel $p
    if ($v.Reason) { Write-Warning "fleet-gate browser: skipping page '$p': $($v.Reason)"; continue }
    if (-not $ok.Contains($v.Path)) { $ok.Add($v.Path) }
    if ($ok.Count -ge $Max) { break }
  }
  return $ok.ToArray()
}

function Invoke-FgBrowserScan {
  # Scans each page in each theme. Returns findings (Check = browser).
  param([string]$RepoPath, [string[]]$Pages, [string]$AxePath, [string]$BrowserPath, [string]$TempDir)
  $out = New-Object System.Collections.Generic.List[object]
  $axe = [System.IO.File]::ReadAllText($AxePath)
  # One server for the scan; its root moves to each page's directory (apps use root-absolute URLs).
  $srv = Start-FgStaticServer -Root $RepoPath
  $br = $null
  try { $br = Start-FgBrowser -BrowserPath $BrowserPath -ProfileDir ([System.IO.Path]::Combine($TempDir, 'browser-profile')) -ServerPort $srv.Port }
  catch { Stop-FgStaticServer $srv; throw }
  $cdp = $null
  try {
    $cdp = Connect-FgCdp -WsUrl $br.PageWs
    $null = Invoke-FgCdp $cdp 'Page.enable'
    foreach ($page in $Pages) {
      $v = Resolve-FgRepoFile -RepoPath $RepoPath -Rel $page
      if ($v.Reason) { $out.Add((New-FgBrowserFinding -Kind 'page-skipped' -Severity 'WARN' -Path $page -Match '' -Note $v.Reason)); continue }
      try {
        $null = Invoke-FgCdp $cdp 'Page.navigate' @{ url = 'about:blank' }
        $srv.State.Root = [System.IO.Path]::GetDirectoryName($v.Full)
        $url = "http://127.0.0.1:$($srv.Port)/$([Uri]::EscapeDataString([System.IO.Path]::GetFileName($v.Full)))"
        $null = Invoke-FgCdp $cdp 'Page.navigate' @{ url = $url }
        $deadline = (Get-Date).AddSeconds(20)
        while ((Invoke-FgEval $cdp 'document.readyState') -ne 'complete' -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
        Start-Sleep -Milliseconds 750
        $null = Invoke-FgEval $cdp ($axe + "`n;true") 120
        foreach ($theme in @('dark', 'light')) {
          $null = Invoke-FgEval $cdp "document.documentElement.setAttribute('data-theme','$theme'); new Promise(r => setTimeout(() => r(true), 300))"
          foreach ($v in @(ConvertFrom-Json (Invoke-FgEval $cdp $script:FgAxeRunJs 180))) {
            if ($null -eq $v) { continue }
            foreach ($n in @($v.nodes)) {
              $out.Add((New-FgBrowserFinding -Kind "axe-$($v.id)" -Severity 'FAIL' -Path $page -Match $n.target -Note "$($v.impact): $($v.help). $($n.summary) ($theme theme)"))
            }
          }
          foreach ($c in @(ConvertFrom-Json (Invoke-FgEval $cdp $script:FgComputedContrastJs 60))) {
            if ($null -eq $c) { continue }
            $out.Add((New-FgBrowserFinding -Kind 'computed-contrast' -Severity 'FAIL' -Path $page -Match "$($c.ratio):1" -Note "$($c.selector) '$($c.text)' $($c.fg) on $($c.bg); needs $($c.min):1 ($theme theme)"))
          }
        }
      } catch {
        $out.Add((New-FgBrowserFinding -Kind 'page-error' -Severity 'WARN' -Path $page -Match '' -Note $_.Exception.Message))
      }
    }
  } finally {
    Stop-FgStaticServer $srv
    if ($cdp) { try { $cdp.Socket.Dispose() } catch { } }
    try { if (-not $br.Process.HasExited) { Stop-Process -Id $br.Process.Id -Force -ErrorAction SilentlyContinue } } catch { }
    Start-Sleep -Milliseconds 500
    try { Remove-Item -LiteralPath $br.ProfileDir -Recurse -Force -ErrorAction SilentlyContinue } catch { }
  }
  return $out
}

function New-FgBrowserFinding {
  param([string]$Kind, [string]$Severity, [string]$Path, [string]$Match, [string]$Note)
  [pscustomobject]@{ Check = 'browser'; Kind = $Kind; Severity = $Severity; Path = $Path; Line = 0; Match = $Match; Note = $Note }
}

Export-ModuleMember -Function *
