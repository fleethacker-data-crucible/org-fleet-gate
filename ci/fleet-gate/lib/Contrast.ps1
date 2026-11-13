# Static WCAG 2.x color-contrast check (no browser). Parses CSS rules and custom properties
# per theme (default, light, dark), works out each text color's background from the same
# rule, from the page's HTML ancestors (for example .nav-label inside aside.sidebar), or from
# the page background, and FAILs below 4.5:1 for normal text (3:1 for large text).

$script:FgNamedColors = @{
  black = '000000'; white = 'ffffff'; red = 'ff0000'; green = '008000'; blue = '0000ff'; yellow = 'ffff00'
  gray = '808080'; grey = '808080'; silver = 'c0c0c0'; maroon = '800000'; purple = '800080'; fuchsia = 'ff00ff'
  lime = '00ff00'; olive = '808000'; navy = '000080'; teal = '008080'; aqua = '00ffff'; orange = 'ffa500'
  darkgray = 'a9a9a9'; darkgrey = 'a9a9a9'; lightgray = 'd3d3d3'; lightgrey = 'd3d3d3'; dimgray = '696969'; dimgrey = '696969'
  gainsboro = 'dcdcdc'; whitesmoke = 'f5f5f5'; ivory = 'fffff0'; beige = 'f5f5dc'; linen = 'faf0e6'; snow = 'fffafa'
  crimson = 'dc143c'; darkred = '8b0000'; darkblue = '00008b'; darkgreen = '006400'; gold = 'ffd700'; goldenrod = 'daa520'
  slategray = '708090'; slategrey = '708090'; lightslategray = '778899'; darkslategray = '2f4f4f'; steelblue = '4682b4'
  royalblue = '4169e1'; dodgerblue = '1e90ff'; tomato = 'ff6347'; coral = 'ff7f50'; salmon = 'fa8072'; tan = 'd2b48c'
  brown = 'a52a2a'; chocolate = 'd2691e'; indigo = '4b0082'; violet = 'ee82ee'; pink = 'ffc0cb'; khaki = 'f0e68c'
  aliceblue = 'f0f8ff'; ghostwhite = 'f8f8ff'; honeydew = 'f0fff0'; mintcream = 'f5fffa'; azure = 'f0ffff'; seashell = 'fff5ee'
  cornsilk = 'fff8dc'; floralwhite = 'fffaf0'; oldlace = 'fdf5e6'; lavender = 'e6e6fa'; midnightblue = '191970'; darkorange = 'ff8c00'
}

function ConvertFrom-FgHex {
  param([string]$Hex)
  $h = $Hex.TrimStart('#')
  if ($h.Length -eq 3 -or $h.Length -eq 4) { $h = (($h.ToCharArray() | ForEach-Object { "$_$_" }) -join '') }
  if ($h.Length -ne 6 -and $h.Length -ne 8) { return $null }
  $r = [Convert]::ToInt32($h.Substring(0, 2), 16); $g = [Convert]::ToInt32($h.Substring(2, 2), 16); $b = [Convert]::ToInt32($h.Substring(4, 2), 16)
  $a = 1.0; if ($h.Length -eq 8) { $a = [Convert]::ToInt32($h.Substring(6, 2), 16) / 255.0 }
  return @([double]$r, [double]$g, [double]$b, [double]$a)
}

function ConvertFrom-FgCssNumber {
  param([string]$Text, [double]$PercentOf = 255)
  $t = $Text.Trim()
  if ($t.EndsWith('%')) { return [double]::Parse($t.TrimEnd('%'), [Globalization.CultureInfo]::InvariantCulture) * $PercentOf / 100.0 }
  return [double]::Parse($t, [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertFrom-FgCssColor {
  # Returns @(r, g, b, a) for one CSS color token, or $null.
  param([string]$Value)
  if ($null -eq $Value) { return $null }
  $v = $Value.Trim().ToLowerInvariant()
  if ($v -eq 'transparent') { return @(0.0, 0.0, 0.0, 0.0) }
  if ($v -match '^#[0-9a-f]{3,8}$') { return (ConvertFrom-FgHex $v) }
  if ($script:FgNamedColors.ContainsKey($v)) { return (ConvertFrom-FgHex $script:FgNamedColors[$v]) }
  try {
    if ($v -match '^rgba?\(([^)]*)\)$') {
      $p = @($Matches[1] -split '[\s,/]+' | Where-Object { $_ })
      if ($p.Count -lt 3) { return $null }
      $a = 1.0; if ($p.Count -ge 4) { $a = ConvertFrom-FgCssNumber $p[3] 1 }
      return @((ConvertFrom-FgCssNumber $p[0]), (ConvertFrom-FgCssNumber $p[1]), (ConvertFrom-FgCssNumber $p[2]), [double]$a)
    }
    if ($v -match '^hsla?\(([^)]*)\)$') {
      $p = @($Matches[1] -split '[\s,/]+' | Where-Object { $_ })
      if ($p.Count -lt 3) { return $null }
      $hh = [double]::Parse(($p[0] -replace 'deg$', ''), [Globalization.CultureInfo]::InvariantCulture) / 360.0
      $s = (ConvertFrom-FgCssNumber $p[1] 1); $l = (ConvertFrom-FgCssNumber $p[2] 1)
      $a = 1.0; if ($p.Count -ge 4) { $a = ConvertFrom-FgCssNumber $p[3] 1 }
      $hh = $hh - [Math]::Floor($hh)
      $q = 0.0; if ($l -lt 0.5) { $q = $l * (1 + $s) } else { $q = $l + $s - $l * $s }
      $pp = 2 * $l - $q
      $rgb = @()
      foreach ($tt in @(($hh + 1.0 / 3), $hh, ($hh - 1.0 / 3))) {
        $t = $tt; if ($t -lt 0) { $t += 1 }; if ($t -gt 1) { $t -= 1 }
        $c = $pp
        if ($t -lt 1.0 / 6) { $c = $pp + ($q - $pp) * 6 * $t } elseif ($t -lt 0.5) { $c = $q } elseif ($t -lt 2.0 / 3) { $c = $pp + ($q - $pp) * (2.0 / 3 - $t) * 6 }
        $rgb += [Math]::Round($c * 255)
      }
      return @([double]$rgb[0], [double]$rgb[1], [double]$rgb[2], [double]$a)
    }
  } catch { return $null }
  return $null
}

function Get-FgBackgroundColorToken {
  # Pulls the color out of a background / background-color value. Returns $null when the
  # value is an image, gradient or otherwise not one plain color.
  param([string]$Value)
  if ($null -eq $Value) { return $null }
  if ($Value.Trim() -eq 'none') { return @(0.0, 0.0, 0.0, 0.0) }
  if ($Value -match '(?i)url\(|gradient\(|image-set\(|color-mix\(|light-dark\(|\bfrom\b|calc\(|var\(') { return $null }
  $c = ConvertFrom-FgCssColor $Value
  if ($c) { return $c }
  $tokens = [regex]::Matches($Value, '#[0-9a-fA-F]{3,8}\b|(?:rgba?|hsla?)\([^)]*\)|\b[a-zA-Z]+\b')
  foreach ($t in $tokens) { $c = ConvertFrom-FgCssColor $t.Value; if ($c) { return $c } }
  return $null
}

function Get-FgLuminance {
  param([double[]]$Rgb)
  $l = @()
  for ($i = 0; $i -lt 3; $i++) {
    $c = $Rgb[$i] / 255.0
    if ($c -le 0.04045) { $l += $c / 12.92 } else { $l += [Math]::Pow(($c + 0.055) / 1.055, 2.4) }
  }
  return 0.2126 * $l[0] + 0.7152 * $l[1] + 0.0722 * $l[2]
}

function Get-FgContrastRatio {
  # WCAG 2.x contrast ratio between two opaque colors (@(r,g,b[,a])).
  param([double[]]$Fore, [double[]]$Back)
  $a = Get-FgLuminance $Fore; $b = Get-FgLuminance $Back
  $hi = [Math]::Max($a, $b); $lo = [Math]::Min($a, $b)
  return ($hi + 0.05) / ($lo + 0.05)
}

function Merge-FgColor {
  # Composites a color with alpha over an opaque backdrop.
  param([double[]]$Top, [double[]]$Under)
  $a = $Top[3]
  return @(($Top[0] * $a + $Under[0] * (1 - $a)), ($Top[1] * $a + $Under[1] * (1 - $a)), ($Top[2] * $a + $Under[2] * (1 - $a)), 1.0)
}

function Format-FgColor { param([double[]]$C) return ('#{0:x2}{1:x2}{2:x2}' -f [int][Math]::Round($C[0]), [int][Math]::Round($C[1]), [int][Math]::Round($C[2])) }

function Resolve-FgCssVars {
  # Expands var(--x[, fallback]) using Local then Vars. Returns $null when unresolved.
  param([string]$Value, [hashtable]$Vars, [hashtable]$Local, [int]$Depth = 0)
  if ($null -eq $Value) { return $null }
  if ($Depth -gt 10) { return $null }
  $v = $Value
  while ($true) {
    $i = $v.IndexOf('var(')
    if ($i -lt 0) { break }
    $d = 0; $j = $i + 3; $end = -1
    for ($k = $j; $k -lt $v.Length; $k++) {
      if ($v[$k] -eq '(') { $d++ } elseif ($v[$k] -eq ')') { $d--; if ($d -eq 0) { $end = $k; break } }
    }
    if ($end -lt 0) { return $null }
    $inner = $v.Substring($i + 4, $end - $i - 4)
    $comma = $inner.IndexOf(',')
    $name = $inner; $fb = $null
    if ($comma -ge 0) { $name = $inner.Substring(0, $comma); $fb = $inner.Substring($comma + 1) }
    $name = $name.Trim()
    $rep = $null
    if ($Local -and $Local.ContainsKey($name)) { $rep = $Local[$name] }
    elseif ($Vars -and $Vars.ContainsKey($name)) { $rep = $Vars[$name] }
    elseif ($null -ne $fb) { $rep = $fb }
    if ($null -eq $rep) { return $null }
    $rep = Resolve-FgCssVars -Value $rep -Vars $Vars -Local $Local -Depth ($Depth + 1)
    if ($null -eq $rep) { return $null }
    $v = $v.Substring(0, $i) + $rep + $v.Substring($end + 1)
  }
  return $v.Trim()
}

function ConvertFrom-FgCss {
  # Parses CSS text into style rules: File, Line, Selector, Media, Decls (Name, Value, Line).
  param([string]$Text, [string]$File)
  $clean = [regex]::Replace($Text, '/\*[\s\S]*?\*/', [System.Text.RegularExpressions.MatchEvaluator] { param($m) [regex]::Replace($m.Value, '[^\n]', ' ') })
  $starts = New-Object System.Collections.Generic.List[int]; $starts.Add(0)
  for ($i = 0; $i -lt $clean.Length; $i++) { if ($clean[$i] -eq "`n") { $starts.Add($i + 1) } }
  $lineOf = { param($off) $idx = $starts.BinarySearch($off); if ($idx -lt 0) { $idx = (-bnot $idx) - 1 }; $idx + 1 }
  $rules = New-Object System.Collections.Generic.List[object]
  $media = New-Object System.Collections.Generic.List[string]
  $seg = 0; $i = 0; $n = $clean.Length
  while ($i -lt $n) {
    $ch = $clean[$i]
    if ($ch -eq '{') {
      $pre = $clean.Substring($seg, $i - $seg)
      $preTrim = $pre.Trim()
      $preOff = $seg + ($pre.Length - $pre.TrimStart().Length)
      if ($preTrim.StartsWith('@')) {
        if ($preTrim -match '^@(?:media|supports|layer|container|document|scope)\b') { $media.Add($preTrim); $i++; $seg = $i; continue }
        # @keyframes, @font-face, @page ...: skip the whole block
        $d = 1; $k = $i + 1
        while ($k -lt $n -and $d -gt 0) { if ($clean[$k] -eq '{') { $d++ } elseif ($clean[$k] -eq '}') { $d-- }; $k++ }
        $i = $k; $seg = $i; continue
      }
      $close = $clean.IndexOf('}', $i + 1)
      if ($close -lt 0) { $close = $n }
      $body = $clean.Substring($i + 1, $close - $i - 1)
      if ($body.Contains('{')) {
        # nested rules (CSS nesting) are not modelled: skip the block
        $d = 1; $k = $i + 1
        while ($k -lt $n -and $d -gt 0) { if ($clean[$k] -eq '{') { $d++ } elseif ($clean[$k] -eq '}') { $d-- }; $k++ }
        $i = $k; $seg = $i; continue
      }
      $decls = New-Object System.Collections.Generic.List[object]
      $pd = 0; $ds = 0
      for ($k = 0; $k -le $body.Length; $k++) {
        $c = ' '; if ($k -lt $body.Length) { $c = $body[$k] }
        if ($c -eq '(') { $pd++ } elseif ($c -eq ')') { $pd-- }
        if (($c -eq ';' -and $pd -le 0) -or $k -eq $body.Length) {
          $decl = $body.Substring($ds, $k - $ds)
          $colon = $decl.IndexOf(':')
          if ($colon -gt 0) {
            $name = $decl.Substring(0, $colon).Trim()
            $val = ($decl.Substring($colon + 1) -replace '!\s*important', '').Trim()
            if (-not $name.StartsWith('--')) { $name = $name.ToLowerInvariant() }
            $off = $i + 1 + $ds + ($decl.Length - $decl.TrimStart().Length)
            if ($name) { $decls.Add([pscustomobject]@{ Name = $name; Value = $val; Line = (& $lineOf $off) }) }
          }
          $ds = $k + 1
        }
      }
      $rules.Add([pscustomobject]@{ File = $File; Line = (& $lineOf $preOff); Selector = ($preTrim -replace '\s+', ' '); Media = ($media -join ' and '); Decls = $decls })
      $i = $close + 1; $seg = $i; continue
    }
    if ($ch -eq '}') { if ($media.Count -gt 0) { $media.RemoveAt($media.Count - 1) }; $i++; $seg = $i; continue }
    if ($ch -eq ';') { $i++; $seg = $i; continue }
    $i++
  }
  return $rules
}

function Split-FgSelectorList {
  # Splits "a, b:not(.x, .y)" on top-level commas.
  param([string]$Selector)
  $out = @(); $d = 0; $s = 0
  for ($i = 0; $i -le $Selector.Length; $i++) {
    $c = ','; if ($i -lt $Selector.Length) { $c = $Selector[$i] }
    if ($c -eq '(' -or $c -eq '[') { $d++ } elseif ($c -eq ')' -or $c -eq ']') { $d-- }
    if ($c -eq ',' -and $d -le 0) { $t = $Selector.Substring($s, $i - $s).Trim(); if ($t) { $out += $t }; $s = $i + 1 }
  }
  return $out
}

function Get-FgSelectorInfo {
  # Theme (default/light/dark/skip), and the compound list without a leading :root/html qualifier.
  param([string]$Item, [string]$Media, [string]$App = '', [string]$Skin = '')
  $theme = 'default'
  if ($App -and $Item -match "data-app\s*=\s*['""]?([A-Za-z0-9_-]+)" -and $Matches[1] -ne $App) { $theme = 'skip' }
  if ($Media -match '(?i)\bprint\b' -and $Media -notmatch '(?i)\bscreen\b') { $theme = 'skip' }
  if ($theme -eq 'skip') { }
  elseif ($Media -match '(?i)prefers-color-scheme\s*:\s*light') { $theme = 'light' }
  elseif ($Media -match '(?i)prefers-color-scheme\s*:\s*dark') { $theme = 'dark' }
  $noNot = [regex]::Replace($Item, ':not\((?:[^()]|\([^()]*\))*\)', '')
  if ($noNot -match "data-skin\s*=\s*['""]?([A-Za-z0-9_-]+)" -and $Matches[1] -cne $Skin) { $theme = 'skip' }
  if ($theme -eq 'skip') { }
  elseif ($noNot -match "(?i)data-theme\s*[~|^]?=\s*['""]?light") { $theme = 'light' }
  elseif ($noNot -match "(?i)data-theme\s*[~|^]?=\s*['""]?dark") { $theme = 'dark' }
  elseif ($noNot -match '(?i)^(?:html|:root)[^\s>]*\.(?:vscode-)?light\b') { $theme = 'light' }
  elseif ($noNot -match '(?i)^(?:html|:root)[^\s>]*\.(?:vscode-)?dark\b') { $theme = 'dark' }
  $state = ($Item -match '(?i)::|:(?:hover|focus|focus-visible|focus-within|active|visited|checked|disabled|indeterminate|placeholder-shown|target)\b|\[(?:disabled|aria-disabled)')
  # split into compounds on combinators (space, >, +, ~) outside brackets/parens
  $parts = @(); $edges = @(); $child = $false; $d = 0; $cur = ''
  foreach ($c in $Item.ToCharArray()) {
    if ($c -eq '(' -or $c -eq '[') { $d++ } elseif ($c -eq ')' -or $c -eq ']') { $d-- }
    if ($d -le 0 -and ($c -eq ' ' -or $c -eq '>' -or $c -eq '+' -or $c -eq '~')) {
      if ($cur) { if ($parts.Count) { $edges += $child }; $parts += $cur; $child = $false }; $cur = ''
      if ($c -eq '>') { $child = $true }
      continue
    }
    $cur += $c
  }
  if ($cur) { if ($parts.Count) { $edges += $child }; $parts += $cur }
  $global = $false; $rootSpec = 0
  if ($parts.Count -gt 0 -and $parts[0] -match '^(?::root|html)(?:$|[\[:.])') {
    if ($parts.Count -eq 1) { $global = $true } else { $rootSpec = Get-FgSpecificity @((ConvertFrom-FgCompound $parts[0])); if ($parts[0] -match '^:root') { $rootSpec += 100 }; $parts = @($parts | Select-Object -Skip 1); $edges = @($edges | Select-Object -Skip 1) }
  }
  if ($parts.Count -eq 1 -and ($parts[0] -match '^(?:body|\*)(?:$|[\[:.])' -or $parts[0] -match '^\[data-(?:theme|app)')) { $global = $true }
  return [pscustomobject]@{ Theme = $theme; Compounds = $parts; DirectChildren = $edges; Global = $global; State = $state; RootSpec = $rootSpec }
}

function ConvertFrom-FgCompound {
  param([string]$Compound)
  $c = [regex]::Replace($Compound, ':not\((?:[^()]|\([^()]*\))*\)|::?[a-zA-Z-]+(?:\([^)]*\))?', '')
  $tag = ''; if ($c -match '^([a-zA-Z][a-zA-Z0-9-]*)') { $tag = $Matches[1].ToLowerInvariant() }
  $id = ''; if ($c -match '#([A-Za-z0-9_-]+)') { $id = $Matches[1] }
  $cls = @([regex]::Matches($c, '\.([A-Za-z0-9_-]+)') | ForEach-Object { $_.Groups[1].Value })
  $attrs = @([regex]::Matches($c, '\[\s*([A-Za-z0-9_-]+)') | ForEach-Object { $_.Groups[1].Value.ToLowerInvariant() })
  return [pscustomobject]@{ Tag = $tag; Id = $id; Classes = $cls; Attrs = $attrs; Star = ($c -eq '*') }
}

function Test-FgCompoundMatch {
  param($Compound, $Node)
  if ($Compound.Tag -and $Compound.Tag -ne $Node.Tag) { return $false }
  if ($Compound.Id -and $Compound.Id -ne $Node.Id) { return $false }
  foreach ($c in $Compound.Classes) { if ($Node.Classes -notcontains $c) { return $false } }
  foreach ($a in $Compound.Attrs) { if ($Node.Attrs -notcontains $a) { return $false } }
  if (-not $Compound.Tag -and -not $Compound.Id -and $Compound.Classes.Count -eq 0 -and $Compound.Attrs.Count -eq 0 -and -not $Compound.Star) { return $false }
  return $true
}

function ConvertFrom-FgHtml {
  # Minimal HTML tree: Tag, Id, Classes, Attrs, Parent. Scripts and styles are skipped.
  param([string]$Text, [string]$File)
  $nodes = New-Object System.Collections.Generic.List[object]
  $void = @('area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'source', 'track', 'wbr', 'param')
  $t = [regex]::Replace($Text, '(?is)<!--.*?-->|<script\b.*?</script\s*>|<style\b.*?</style\s*>', '')
  $stack = New-Object System.Collections.Generic.List[object]
  foreach ($m in [regex]::Matches($t, '<(/?)([a-zA-Z][a-zA-Z0-9-]*)((?:[^>"'']|"[^"]*"|''[^'']*'')*)>')) {
    $tag = $m.Groups[2].Value.ToLowerInvariant()
    if ($m.Groups[1].Value -eq '/') {
      for ($k = $stack.Count - 1; $k -ge 0; $k--) { if ($stack[$k].Tag -eq $tag) { $stack.RemoveRange($k, $stack.Count - $k); break } }
      continue
    }
    $attrText = $m.Groups[3].Value
    $cls = @(); if ($attrText -match '(?i)\bclass\s*=\s*(?:"([^"]*)"|''([^'']*)''|([^\s>]+))') { $cls = @(("$($Matches[1])$($Matches[2])$($Matches[3])" -split '\s+') | Where-Object { $_ }) }
    $id = ''; if ($attrText -match '(?i)\bid\s*=\s*(?:"([^"]*)"|''([^'']*)''|([^\s>]+))') { $id = "$($Matches[1])$($Matches[2])$($Matches[3])" }
    $attrs = @([regex]::Matches($attrText, '(?:^|\s)([A-Za-z_:][A-Za-z0-9_:.-]*)') | ForEach-Object { $_.Groups[1].Value.ToLowerInvariant() })
    $parent = $null; if ($stack.Count -gt 0) { $parent = $stack[$stack.Count - 1] }
    $app = ''; if ($attrText -match "(?i)\bdata-app\s*=\s*[""']?([A-Za-z0-9_-]+)") { $app = $Matches[1] }
    $node = [pscustomobject]@{ Tag = $tag; Id = $id; Classes = $cls; Attrs = $attrs; Parent = $parent; File = $File; App = $app }
    $nodes.Add($node)
    if (($void -notcontains $tag) -and -not $attrText.TrimEnd().EndsWith('/')) { $stack.Add($node) }
  }
  return $nodes
}

function Get-FgCompoundKey {
  param($Compound)
  if ($Compound.Id) { return "i:$($Compound.Id)" }
  if ($Compound.Classes.Count -gt 0) { return "c:$($Compound.Classes[0])" }
  if ($Compound.Tag) { return "t:$($Compound.Tag)" }
  return '*'
}

function Get-FgNodeKeys {
  param($Node)
  $k = @('*', "t:$($Node.Tag)")
  if ($Node.Id) { $k += "i:$($Node.Id)" }
  foreach ($c in $Node.Classes) { $k += "c:$c" }
  return $k
}

function Get-FgDecl {
  param($Rule, [string]$Name)
  $v = $null
  foreach ($d in $Rule.Decls) { if ($d.Name -eq $Name) { $v = $d } }
  return $v
}

function Get-FgLocalVars {
  param($Rule)
  $h = @{}
  foreach ($d in $Rule.Decls) { if ($d.Name.StartsWith('--')) { $h[$d.Name] = $d.Value } }
  return $h
}

function Get-FgSpecificity {
  # Rough CSS specificity: ids * 10000 + (classes + attributes) * 100 + tags.
  param([object[]]$Compounds)
  $n = 0
  foreach ($c in @($Compounds)) { if ($c.Id) { $n += 10000 }; $n += 100 * (@($c.Classes).Count + @($c.Attrs).Count); if ($c.Tag) { $n += 1 } }
  return $n
}

function Test-FgColorOverridden {
  # True when another color rule that also matches Node takes precedence over Text.
  param($Model, $Text, $Node, [string]$Theme = '')
  foreach ($o in $Model.Texts) {
    if ($o.Order -eq $Text.Order -or $o.Compounds.Count -eq 0) { continue }
    if ($Theme) {
      if ($o.Theme -ne 'default' -and $o.Theme -ne $Theme) { continue }
    } else {
      if ($o.Theme -ne 'default' -and $Text.Theme -ne 'default' -and $o.Theme -ne $Text.Theme) { continue }
      if ($o.Theme -ne 'default' -and $Text.Theme -eq 'default') { continue }
    }
    if ($o.Spec -lt $Text.Spec -or ($o.Spec -eq $Text.Spec -and $o.Order -lt $Text.Order)) { continue }
    if (-not (Test-FgCompoundMatch $o.Compounds[$o.Compounds.Count - 1] $Node)) { continue }
    if (Test-FgProviderMatchesNode ([pscustomobject]@{ Compounds = $o.Compounds; DirectChildren = $o.DirectChildren }) $Node) { return $true }
  }
  return $false
}

function Get-FgCssModel {
  # Builds theme variable maps, background providers and text-color rules.
  # App: the page's <html data-app="..."> value; other apps' [data-app] rules are ignored.
  param([object[]]$Rules, [string]$App = '', [string]$Skin = '')
  $vars = @{ default = @{}; light = @{}; dark = @{} }
  $varFiles = @{}
  $providers = New-Object System.Collections.Generic.List[object]
  $texts = New-Object System.Collections.Generic.List[object]
  foreach ($r in $Rules) {
    foreach ($item in (Split-FgSelectorList $r.Selector)) {
      $info = Get-FgSelectorInfo -Item $item -Media $r.Media -App $App -Skin $Skin
      if ($info.Theme -eq 'skip') { continue }
      if ($info.Global) {
        foreach ($d in $r.Decls) { if ($d.Name.StartsWith('--')) { $vars[$info.Theme][$d.Name] = $d.Value; $varFiles[$r.File] = $true } }
      }
      if ($info.State) { continue }
      $bg = Get-FgDecl $r 'background-color'; if (-not $bg) { $bg = Get-FgDecl $r 'background' }
      $fg = Get-FgDecl $r 'color'
      $compounds = @($info.Compounds | ForEach-Object { ConvertFrom-FgCompound $_ })
      if ($bg -and $compounds.Count -ge 1) {
        $providers.Add([pscustomobject]@{ Order = $providers.Count; Rule = $r; Decl = $bg; Theme = $info.Theme; Compounds = $compounds; DirectChildren = $info.DirectChildren; Spec = ((Get-FgSpecificity $compounds) + $info.RootSpec); Global = $info.Global -or ($compounds.Count -eq 1 -and $compounds[0].Tag -match '^(html|body)$') })
      }
      if ($fg) { $texts.Add([pscustomobject]@{ Order = $texts.Count; Rule = $r; Decl = $fg; Bg = $bg; Theme = $info.Theme; Item = $item; Compounds = $compounds; DirectChildren = $info.DirectChildren; Spec = ((Get-FgSpecificity $compounds) + $info.RootSpec) }) }
    }
  }
  $themes = @('default')
  if ($vars.light.Count -gt 0) { $themes += 'light' }
  if ($vars.dark.Count -gt 0) { $themes += 'dark' }
  $pidx = @{}
  foreach ($p in $providers) {
    $key = Get-FgCompoundKey $p.Compounds[$p.Compounds.Count - 1]
    if (-not $pidx.ContainsKey($key)) { $pidx[$key] = New-Object System.Collections.Generic.List[object] }
    $pidx[$key].Add($p)
  }
  return [pscustomobject]@{ Vars = $vars; VarFiles = $varFiles; Providers = $providers; ProviderIndex = $pidx; Texts = $texts; Themes = $themes; BgCache = @{} }
}

function Get-FgThemeVars {
  param($Model, [string]$Theme)
  $h = @{}
  foreach ($k in $Model.Vars.default.Keys) { $h[$k] = $Model.Vars.default[$k] }
  if ($Theme -ne 'default') { foreach ($k in $Model.Vars[$Theme].Keys) { $h[$k] = $Model.Vars[$Theme][$k] } }
  return $h
}

function Resolve-FgColorDecl {
  # Resolves a color/background declaration in a theme. Returns color array or $null.
  param($Decl, $Rule, [hashtable]$Vars, [switch]$Background)
  $val = Resolve-FgCssVars -Value $Decl.Value -Vars $Vars -Local (Get-FgLocalVars $Rule)
  if ($null -eq $val) { return $null }
  if ($Background) { return (Get-FgBackgroundColorToken $val) }
  return (ConvertFrom-FgCssColor $val)
}

function Test-FgProviderMatchesNode {
  param($Provider, $Node)
  $cs = $Provider.Compounds
  return (Test-FgAncestorChain $cs @($Provider.DirectChildren) ($cs.Count - 1) $Node)
}

function Test-FgAncestorChain {
  param([object[]]$Compounds, [object[]]$DirectChildren, [int]$Index, $Node)
  if (-not $Node -or -not (Test-FgCompoundMatch $Compounds[$Index] $Node)) { return $false }
  if ($Index -eq 0) { return $true }
  $p = $Node.Parent
  if ($DirectChildren.Count -ge $Index -and $DirectChildren[$Index - 1]) { return (Test-FgAncestorChain $Compounds $DirectChildren ($Index - 1) $p) }
  while ($p) { if (Test-FgAncestorChain $Compounds $DirectChildren ($Index - 1) $p) { return $true }; $p = $p.Parent }
  return $false
}

function Get-FgPageBackground {
  param($Model, [string]$Theme, [hashtable]$Vars)
  $best = $null
  foreach ($p in $Model.Providers) {
    if (-not $p.Global) { continue }
    if ($p.Theme -ne 'default' -and $p.Theme -ne $Theme) { continue }
    if ($Model.Nodes.Count -gt 0 -and $p.Compounds[-1].Tag -eq 'body' -and -not @($Model.Nodes | Where-Object { $_.Tag -eq 'body' -and (Test-FgProviderMatchesNode $p $_) }).Count) { continue }
    $isBody = $p.Compounds[-1].Tag -eq 'body'
    if ($best -and (($best.IsBody -and -not $isBody) -or ($best.IsBody -eq $isBody -and ($p.Spec -lt $best.Spec -or ($p.Spec -eq $best.Spec -and $p.Order -lt $best.Order))))) { continue }
    $c = Resolve-FgColorDecl -Decl $p.Decl -Rule $p.Rule -Vars $Vars -Background
    if ($c -and $c[3] -gt 0) { $best = [pscustomobject]@{ Color = $c; Source = "page background ($($p.Rule.Selector), $($p.Rule.File):$($p.Decl.Line))"; File = $p.Rule.File; Spec = $p.Spec; Order = $p.Order; IsBody = $isBody } }
  }
  return $best
}

function Get-FgNodeBackground {
  # Walks up from Node and returns the first ancestor-or-self background in this theme.
  param($Model, $Node, [string]$Theme, [hashtable]$Vars)
  $ck = "$([System.Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($Node))|$Theme"
  if ($Model.BgCache.ContainsKey($ck)) { return $Model.BgCache[$ck] }
  $res = Get-FgNodeBackgroundUncached $Model $Node $Theme $Vars
  $Model.BgCache[$ck] = $res
  return $res
}

function Get-FgNodeBackgroundUncached {
  param($Model, $Node, [string]$Theme, [hashtable]$Vars)
  $n = $Node
  $layers = New-Object System.Collections.Generic.List[object]
  $source = $null
  while ($n) {
    $hit = $null
    foreach ($key in (Get-FgNodeKeys $n)) {
      if (-not $Model.ProviderIndex.ContainsKey($key)) { continue }
      foreach ($p in $Model.ProviderIndex[$key]) {
        if ($p.Theme -ne 'default' -and $p.Theme -ne $Theme) { continue }
        if ($hit -and ($p.Spec -lt $hit.Spec -or ($p.Spec -eq $hit.Spec -and $p.Order -lt $hit.Order))) { continue }
        if (Test-FgProviderMatchesNode $p $n) { $hit = $p }
      }
    }
    if ($hit) {
      if (-not $source) { $source = $hit }
      $c = Resolve-FgColorDecl -Decl $hit.Decl -Rule $hit.Rule -Vars $Vars -Background
      if ($null -eq $c) { return [pscustomobject]@{ Color = $null; Source = "$($hit.Rule.Selector) ($($hit.Rule.File):$($hit.Decl.Line))"; File = $hit.Rule.File } }
      if ($c[3] -gt 0.999) {
        for ($i = $layers.Count - 1; $i -ge 0; $i--) { $c = Merge-FgColor $layers[$i] $c }
        return [pscustomobject]@{ Color = $c; Source = "inside $($source.Rule.Selector) ($($source.Rule.File):$($source.Decl.Line))"; File = $source.Rule.File }
      }
      if ($c[3] -gt 0) { $layers.Add($c) }
    }
    $n = $n.Parent
  }
  if ($layers.Count) {
    $pg = Get-FgPageBackground $Model $Theme $Vars
    if ($pg) {
      $c = $pg.Color
      for ($i = $layers.Count - 1; $i -ge 0; $i--) { $c = Merge-FgColor $layers[$i] $c }
      return [pscustomobject]@{ Color = $c; Source = "inside $($source.Rule.Selector) ($($source.Rule.File):$($source.Decl.Line))"; File = $source.Rule.File }
    }
  }
  return $null
}

function New-FgSelectorNode {
  # Dynamic UI markup may not occur in the initial HTML. Preserve its selector
  # chain so the same precedence and ancestor-background rules still apply.
  param([object[]]$Compounds)
  $parent = $null
  foreach ($c in $Compounds) {
    $tag = $c.Tag; if (-not $tag) { $tag = 'div' }
    $parent = [pscustomobject]@{ Tag = $tag; Id = $c.Id; Classes = @($c.Classes); Attrs = @($c.Attrs); Parent = $parent }
  }
  return $parent
}

function Find-FgContrast {
  # Rules: parsed CSS rules. Nodes: parsed HTML nodes. ChangedPaths: PR paths (FAIL vs WARN).
  param([object[]]$Rules, [object[]]$Nodes, [string[]]$ChangedPaths, [switch]$FullScan, [double]$Minimum = 4.5, [double]$LargeMinimum = 3.0, [string]$Skin = '', [switch]$SkinPass)
  if (-not $SkinPass) {
    $skins = @($Rules | ForEach-Object {
      foreach ($m in [regex]::Matches($_.Selector, "data-skin\s*=\s*['""]?([A-Za-z0-9_-]+)")) { $m.Groups[1].Value }
    } | Sort-Object -Unique)
    if ($skins.Count -gt 0) {
      foreach ($variant in @('') + $skins) {
        foreach ($finding in @(Find-FgContrast -Rules $Rules -Nodes $Nodes -ChangedPaths $ChangedPaths -FullScan:$FullScan -Minimum $Minimum -LargeMinimum $LargeMinimum -Skin $variant -SkinPass)) {
          $name = 'default'; if ($variant) { $name = $variant }
          $finding.Note += "; skin $name"
          $finding
        }
      }
      return
    }
  }
  $out = New-Object System.Collections.Generic.List[object]
  $app = ''
  foreach ($nd in @($Nodes)) { if ($nd -and $nd.Tag -eq 'html' -and $nd.App) { $app = $nd.App; break } }
  $model = Get-FgCssModel -Rules $Rules -App $app -Skin $Skin
  $model | Add-Member -NotePropertyName Nodes -NotePropertyValue @($Nodes)
  $changed = @{}; foreach ($c in @($ChangedPaths)) { if ($c) { $changed[$c] = $true } }
  $tokenChanged = $false; foreach ($f in $model.VarFiles.Keys) { if ($changed.ContainsKey($f)) { $tokenChanged = $true } }
  $seen = @{}
  $nidx = @{}
  foreach ($nd in @($Nodes)) {
    if ($null -eq $nd) { continue }
    foreach ($key in (Get-FgNodeKeys $nd)) {
      if (-not $nidx.ContainsKey($key)) { $nidx[$key] = New-Object System.Collections.Generic.List[object] }
      $nidx[$key].Add($nd)
    }
  }
  foreach ($t in $model.Texts) {
    $last = $null; if ($t.Compounds.Count -gt 0) { $last = $t.Compounds[$t.Compounds.Count - 1] }
    $prov = [pscustomobject]@{ Compounds = $t.Compounds; DirectChildren = $t.DirectChildren }
    $matched = @()
    if ($last) {
      $key = Get-FgCompoundKey $last
      if ($nidx.ContainsKey($key)) { $matched = @($nidx[$key] | Where-Object { Test-FgProviderMatchesNode $prov $_ }) }
    }
    if ($matched.Count -eq 0 -and $last) { $matched = @(New-FgSelectorNode $t.Compounds) }
    foreach ($theme in $model.Themes) {
      if ($t.Theme -ne 'default' -and $t.Theme -ne $theme) { continue }
      $activeMatched = @($matched | Where-Object { -not (Test-FgColorOverridden $model $t $_ -Theme $theme) })
      if ($matched.Count -gt 0 -and $activeMatched.Count -eq 0) { continue }
      $vars = Get-FgThemeVars $model $theme
      $fg = Resolve-FgColorDecl -Decl $t.Decl -Rule $t.Rule -Vars $vars
      # Fully transparent glyphs (for example a decorative highlight backing
      # layer) are not visible text. Partial alpha still gets composited and tested.
      if ($fg -and $fg[3] -eq 0) { continue }
      $val = ($t.Decl.Value).Trim().ToLowerInvariant()
      if ($val -match '^(inherit|initial|unset|revert|currentcolor)$') { continue }
      $bgs = @()
      foreach ($node in $activeMatched) { $b = Get-FgNodeBackground $model $node $theme $vars; if ($b) { $bgs += $b } }
      if ($bgs.Count -eq 0 -or $activeMatched.Count -gt $bgs.Count) { $pg = Get-FgPageBackground $model $theme $vars; if ($pg) { $bgs += $pg } }
      $file = $t.Rule.File
      $isChanged = $FullScan -or $tokenChanged -or $changed.ContainsKey($file)
      if ($null -eq $fg -or $bgs.Count -eq 0) {
        if ($isChanged) {
          $k = "u|$file|$($t.Decl.Line)"
          if (-not $seen.ContainsKey($k)) { $seen[$k] = $true; $out.Add((New-FgFinding 'contrast' 'unresolved' 'WARN' $file $t.Decl.Line $t.Item "could not resolve the text color or its background ($theme theme)")) }
        }
        continue
      }
      $size = Get-FgDecl $t.Rule 'font-size'; $weight = Get-FgDecl $t.Rule 'font-weight'
      $min = $Minimum
      if ($size -and $size.Value -match '^\s*([\d.]+)px\s*$') {
        $px = [double]::Parse($Matches[1], [Globalization.CultureInfo]::InvariantCulture)
        $bold = ($weight -and ($weight.Value -match '^(bold|bolder|[7-9]00)$'))
        if ($px -ge 24 -or ($bold -and $px -ge 18.66)) { $min = $LargeMinimum }
      }
      foreach ($b in $bgs) {
        if ($null -eq $b.Color) {
          if ($isChanged) {
            $k = "u|$file|$($t.Decl.Line)|$($b.Source)"
            if (-not $seen.ContainsKey($k)) { $seen[$k] = $true; $out.Add((New-FgFinding 'contrast' 'unresolved' 'WARN' $file $t.Decl.Line $t.Item "background not a plain color: $($b.Source) ($theme theme)")) }
          }
          continue
        }
        $back = $b.Color
        if ($back[3] -lt 0.999) {
          $pg = Get-FgPageBackground $model $theme $vars
          if ($pg) { $back = Merge-FgColor $back $pg.Color } else { continue }
        }
        $front = $fg; if ($front[3] -lt 0.999) { $front = Merge-FgColor $front $back }
        $ratio = Get-FgContrastRatio $front $back
        if ($ratio -lt $min) {
          $k = "f|$file|$($t.Decl.Line)|$(Format-FgColor $front)|$(Format-FgColor $back)"
          $rs = [Math]::Round($ratio, 2).ToString('0.00', [Globalization.CultureInfo]::InvariantCulture)
          if ($seen.ContainsKey($k)) { $seen[$k].Note = $seen[$k].Note -replace '\(([a-z, ]+) theme\)', "(`$1, $theme theme)"; continue }
          $sev = 'WARN'; $pre = 'pre-existing; '
          if ($isChanged -or $changed.ContainsKey($b.File)) { $sev = 'FAIL'; $pre = '' }
          $f = New-FgFinding 'contrast' 'low-contrast' $sev $file $t.Decl.Line "${rs}:1" ("{0}{1} {2} on {3}, {4}; needs {5}:1 ({6} theme)" -f $pre, $t.Item, (Format-FgColor $front), (Format-FgColor $back), $b.Source, $min, $theme)
          $seen[$k] = $f
          $out.Add($f)
        }
      }
    }
  }
  return $out
}

$script:FgCssSkip = '(?i)(?:^|/)(?:node_modules|dist|build|out|coverage|\.git)/|\.min\.css$'

function Find-FgContrastInRepo {
  param([string]$RepoPath, [string[]]$ChangedPaths, [switch]$FullScan)
  $rules = New-Object System.Collections.Generic.List[object]
  $nodes = New-Object System.Collections.Generic.List[object]
  # vendor/ CSS loads first in Fleet pages, so its rules come first (later rules win)
  $files = @(Get-FgTrackedFiles -RepoPath $RepoPath | Sort-Object @{ Expression = { if ($_ -match '(?i)(?:^|/)vendor/') { 0 } else { 1 } } }, @{ Expression = { $_ } })
  foreach ($f in $files) {
    if ($f -match $script:FgCssSkip -or (Test-FgFixturePath $f)) { continue }
    $full = [System.IO.Path]::Combine($RepoPath, $f)
    if ($f -match '(?i)\.css$' -and (Test-FgTextFile -FullPath $full)) { foreach ($r in (ConvertFrom-FgCss -Text ([System.IO.File]::ReadAllText($full)) -File $f)) { $rules.Add($r) } }
    elseif ($f -match '(?i)\.html?$' -and (Test-FgTextFile -FullPath $full)) { foreach ($n in (ConvertFrom-FgHtml -Text ([System.IO.File]::ReadAllText($full)) -File $f)) { $nodes.Add($n) } }
  }
  if ($rules.Count -eq 0) { return @() }
  # A server dashboard and a chat page may use the same token names but different
  # stylesheets. Resolve actual linked CSS (and its local imports) per HTML page.
  # Keep the original whole-repo fallback for build templates without resolvable
  # stylesheet links, and scan unreferenced CSS on its own rather than ignoring it.
  $used = @{}
  $byFile = @{}
  foreach ($r in $rules) { if (-not $byFile.ContainsKey($r.File)) { $byFile[$r.File] = @() }; $byFile[$r.File] += $r }
  $fallback = $false
  $pages = @($nodes | ForEach-Object { $_.File } | Sort-Object -Unique)
  foreach ($page in $pages) {
    $text = [System.IO.File]::ReadAllText([System.IO.Path]::Combine($RepoPath, $page))
    $seen = @{}
    $pageRules = New-Object System.Collections.Generic.List[object]
    function Add-FgPageCss {
      param([string]$Relative, [string]$From)
      $clean = ($Relative -split '[?#]')[0]
      if ($clean -match '^(?:[a-z]+:|//)' -or $clean -match '[%{}]') { return }
      $baseDir = [System.IO.Path]::GetDirectoryName([System.IO.Path]::Combine($RepoPath, $From))
      if ($clean.StartsWith('/')) { $baseDir = $RepoPath; $clean = $clean.TrimStart('/') }
      $absolute = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($baseDir, $clean))
      $prefix = [System.IO.Path]::GetFullPath($RepoPath).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
      if (-not $absolute.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { return }
      $relativePath = $absolute.Substring($prefix.Length).Replace('\', '/')
      if ($seen.ContainsKey($relativePath) -or -not $byFile.ContainsKey($relativePath)) { return }
      $seen[$relativePath] = $true; $used[$relativePath] = $true
      $cssText = [System.IO.File]::ReadAllText($absolute)
      foreach ($m in [regex]::Matches($cssText, '(?i)@import\s+(?:url\(\s*)?["'']([^"'']+)["'']')) { Add-FgPageCss $m.Groups[1].Value $relativePath }
      foreach ($rule in $byFile[$relativePath]) { $pageRules.Add($rule) }
    }
    foreach ($m in [regex]::Matches($text, '(?is)<link\b[^>]*\bhref\s*=\s*["'']([^"'']+\.css(?:[?#][^"'']*)?)["''][^>]*>')) { Add-FgPageCss $m.Groups[1].Value $page }
    if ($pageRules.Count -eq 0) {
      if ($text -match '(?is)<link\b[^>]*\brel\s*=\s*["'']stylesheet["'']') { $fallback = $true }
      continue
    }
    Find-FgContrast -Rules $pageRules.ToArray() -Nodes @($nodes | Where-Object { $_.File -eq $page }) -ChangedPaths $ChangedPaths -FullScan:$FullScan
  }
  if ($fallback -or $pages.Count -eq 0) { return (Find-FgContrast -Rules $rules -Nodes $nodes -ChangedPaths $ChangedPaths -FullScan:$FullScan) }
  $orphan = @($rules | Where-Object { -not $used.ContainsKey($_.File) })
  if ($orphan.Count) { Find-FgContrast -Rules $orphan -Nodes @() -ChangedPaths $ChangedPaths -FullScan:$FullScan }
}
