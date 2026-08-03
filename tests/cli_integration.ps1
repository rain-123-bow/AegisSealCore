param(
    [Parameter(Mandatory = $true)]
    [string]$ExePath,

    [Parameter(Mandatory = $true)]
    [string]$WorkDir
)

$ErrorActionPreference = 'Stop'
$expected = 'ASC1:0cb65a29352e00e8370541f18b04c4f88d881eb93e193a0be9cdcf40763cf00e'
$incorrect = 'ASC1:' + ('0' * 64)

function Invoke-SealProcess {
    param([string[]]$Arguments)

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo.FileName = $ExePath
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    foreach ($argument in $Arguments) {
        $process.StartInfo.ArgumentList.Add($argument)
    }
    try {
        if (-not $process.Start()) {
            throw 'failed to start aegis-seal process'
        }
        $standardOutput = $process.StandardOutput.ReadToEnd()
        $standardError = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            StandardOutput = $standardOutput
            StandardError = $standardError
        }
    } finally {
        $process.Dispose()
    }
}

[System.IO.Directory]::CreateDirectory($WorkDir) | Out-Null
$manifestPath = [System.IO.Path]::Combine($WorkDir, 'fixed-vector.asc1mf')
$stream = [System.IO.File]::Open(
    $manifestPath,
    [System.IO.FileMode]::Create,
    [System.IO.FileAccess]::Write,
    [System.IO.FileShare]::None)
$writer = [System.IO.BinaryWriter]::new($stream, [System.Text.Encoding]::UTF8, $false)
try {
    $writer.Write([byte[]](0x41, 0x53, 0x43, 0x31, 0x4d, 0x46, 0x0d, 0x0a))
    $writer.Write([byte[]](0x10..0x1f))
    $writer.Write([byte[]](0x40..0x4f))
    $writer.Write([uint64]0)
    $writer.Write([byte[]]::new(32))
    $writer.Write([uint32]2)

    foreach ($entry in @(
        @{ Path = 'src/main.cpp'; Content = 'int main' },
        @{ Path = 'include/main.hpp'; Content = '#pragma' }
    )) {
        $pathBytes = [System.Text.Encoding]::UTF8.GetBytes($entry.Path)
        $contentBytes = [System.Text.Encoding]::UTF8.GetBytes($entry.Content)
        $writer.Write([uint32]$pathBytes.Length)
        $writer.Write($pathBytes)
        $writer.Write([uint64]$contentBytes.Length)
        $writer.Write($contentBytes)
    }
} finally {
    $writer.Dispose()
}

$computed = & $ExePath compute $manifestPath
if ($LASTEXITCODE -ne 0 -or $computed -ne $expected) {
    throw "compute failed: exit=$LASTEXITCODE output=$computed"
}

$verified = & $ExePath verify $manifestPath $expected
if ($LASTEXITCODE -ne 0 -or $verified -ne 'MATCH') {
    throw "matching verify failed: exit=$LASTEXITCODE output=$verified"
}

$mismatch = & $ExePath verify $manifestPath $incorrect
if ($LASTEXITCODE -ne 2 -or $mismatch -ne 'MISMATCH') {
    throw "mismatching verify returned the wrong contract: exit=$LASTEXITCODE output=$mismatch"
}

$truncatedPath = [System.IO.Path]::Combine($WorkDir, 'truncated.asc1mf')
$manifestBytes = [System.IO.File]::ReadAllBytes($manifestPath)
[System.IO.File]::WriteAllBytes(
    $truncatedPath,
    $manifestBytes[0..($manifestBytes.Length - 2)])

$truncated = Invoke-SealProcess -Arguments @('compute', $truncatedPath)
if ($truncated.ExitCode -ne 3 -or
    $truncated.StandardOutput.Length -ne 0 -or
    -not $truncated.StandardError.StartsWith('ERROR: ASC-1 manifest is truncated')) {
    throw "invalid manifest returned the wrong contract: exit=$($truncated.ExitCode) stdout=$($truncated.StandardOutput) stderr=$($truncated.StandardError)"
}

[byte[]]$invalidUtf8Bytes = $manifestBytes.Clone()
$invalidUtf8Bytes[92] = 0xff
$invalidUtf8Path = [System.IO.Path]::Combine($WorkDir, 'invalid-utf8.asc1mf')
[System.IO.File]::WriteAllBytes($invalidUtf8Path, $invalidUtf8Bytes)
$invalidUtf8 = Invoke-SealProcess -Arguments @('compute', $invalidUtf8Path)
if ($invalidUtf8.ExitCode -ne 3 -or
    $invalidUtf8.StandardOutput.Length -ne 0 -or
    -not $invalidUtf8.StandardError.StartsWith('ERROR: ASC-1 path is not valid UTF-8')) {
    throw "invalid UTF-8 path returned the wrong contract: exit=$($invalidUtf8.ExitCode) stdout=$($invalidUtf8.StandardOutput) stderr=$($invalidUtf8.StandardError)"
}

Write-Output 'PASS: ASC-1 CLI integration'
