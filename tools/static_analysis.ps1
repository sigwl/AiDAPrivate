[CmdletBinding()]
param(
    [switch]$Fix,
    [switch]$All
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$sourceExtensions = @('.c', '.cc', '.cpp', '.cxx', '.h', '.hh', '.hpp', '.hxx')
$excludedSegments = @(
    '\.deps\',
    '\build-ninja\',
    '\build\',
    '\out\',
    '\vendor\',
    '\third_party\',
    '\generated\',
    '\cmake-build-',
    '\src\whoswho_embedded.h'
)

function Test-FirstPartyPath {
    param([Parameter(Mandatory)][string]$Path)

    $fullPath = [IO.Path]::GetFullPath($Path)
    if (-not $fullPath.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
        return $false
    }

    $relativePath = $fullPath.Substring($root.Length).TrimStart('\', '/')
    $parts = $relativePath -split '[\\/]'
    if ($parts.Count -eq 0 -or $parts[0] -notin @('src', 'driver', 'mapper')) {
        return $false
    }

    if ([IO.Path]::GetExtension($fullPath).ToLowerInvariant() -notin $sourceExtensions) {
        return $false
    }

    foreach ($segment in $excludedSegments) {
        if ($fullPath -match [Regex]::Escape($segment)) {
            return $false
        }
    }

    return $true
}

function Resolve-Tool {
    param([Parameter(Mandatory)][string]$Name)

    $command = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        throw "Required tool not found: $Name"
    }

    return $command.Source
}

function Invoke-Native {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList
    )

    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath"
    }
}

try {
    $clangFormat = Resolve-Tool 'clang-format'
    $clangTidy = Resolve-Tool 'clang-tidy'
    $git = Resolve-Tool 'git'

    $compileDatabase = Get-ChildItem -LiteralPath (Join-Path $root 'build-ninja') -Filter 'compile_commands.json' -File -Recurse -ErrorAction SilentlyContinue |
        Sort-Object FullName |
        Select-Object -First 1
    if ($null -eq $compileDatabase) {
        throw "compile_commands.json not found under build-ninja"
    }

    $paths = [Collections.Generic.List[string]]::new()
    if ($All) {
        $candidatePaths = Get-ChildItem -LiteralPath $root -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { Test-FirstPartyPath $_.FullName } |
            ForEach-Object FullName
    } else {
        $trackedChanges = @(& $git -C $root diff --name-only HEAD --)
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to enumerate changed files"
        }
        $untrackedChanges = @(& $git -C $root ls-files --others --exclude-standard)
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to enumerate untracked files"
        }
        $candidatePaths = @($trackedChanges + $untrackedChanges) |
            Where-Object { $_ -and (Test-Path -LiteralPath (Join-Path $root $_) -PathType Leaf) -and (Test-FirstPartyPath (Join-Path $root $_)) } |
            ForEach-Object { [IO.Path]::GetFullPath((Join-Path $root $_)) }
    }

    foreach ($path in ($candidatePaths | Sort-Object -Unique)) {
        if (-not $paths.Contains($path)) {
            $paths.Add($path)
        }
    }

    Write-Host "compile_commands.json: $($compileDatabase.FullName)"
    Write-Host "Files: $($paths.Count)"
    if ($paths.Count -eq 0) {
        exit 0
    }

    foreach ($path in $paths) {
        $formatArguments = @('--dry-run', '--Werror', '--assume-filename', $path, $path)
        if ($Fix) {
            $formatArguments = @('-i', '--assume-filename', $path, $path)
        }
        Invoke-Native -FilePath $clangFormat -ArgumentList $formatArguments
    }

    $translationUnits = @($paths | Where-Object { [IO.Path]::GetExtension($_).ToLowerInvariant() -in @('.c', '.cc', '.cpp', '.cxx') })
    if ($translationUnits.Count -gt 0) {
        $tidyArguments = @('-p', $compileDatabase.DirectoryName)
        if ($Fix) {
            $tidyArguments += '--fix'
        }
        $tidyArguments += $translationUnits
        Invoke-Native -FilePath $clangTidy -ArgumentList $tidyArguments
    }
    exit 0
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
