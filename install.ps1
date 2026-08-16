# install.ps1 — Windows installer for `ds`.
#
# Default path: download a prebuilt ds.exe from GitHub Releases, verify its
# SHA-256 checksum, and install to ~/.local/bin (creating it if needed).
# No Rust toolchain required.
#
# Fallback path (--FromSource or no matching prebuilt binary exists): build
# from source via the official `rustup` installer (minimal profile) + cargo.
#
# Usage:
#   .\install.ps1                          # install latest release
#   .\install.ps1 -Version v0.1.0          # install a specific release tag
#   .\install.ps1 -FromSource              # force source build
#   irm https://raw.githubusercontent.com/mirzasaikatahmmed/ds-cli/main/install.ps1 | iex
#
# Environment:
#   DS_INSTALL_DIR       Override install directory (default: ~/.local/bin)
#   DS_GITHUB_REPO       Override repo (default: mirzasaikatahmmed/ds-cli)
#   DS_SKIP_CHECKSUM     Set to "1" to skip checksum verification

[CmdletBinding()]
param(
    [string]$Version = "",
    [switch]$FromSource = $false,
    [string]$Repo = ""
)

$ErrorActionPreference = "Stop"

if (-not $Repo) {
    $Repo = if ($env:DS_GITHUB_REPO) { $env:DS_GITHUB_REPO } else { "mirzasaikatahmmed/ds-cli" }
}

$SkipChecksum = ($env:DS_SKIP_CHECKSUM -eq "1")

function Write-Log {
    param([string]$Message)
    Write-Host "[ds install] $Message"
}

function Write-Err {
    param([string]$Message)
    Write-Host "[ds install] error: $Message" -ForegroundColor Red
}

function Get-Target {
    $arch = [System.Environment]::Is64BitOperatingSystem
    if (-not $arch) {
        Write-Err "32-bit Windows is not supported"
        return $null
    }
    if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq "Arm64") {
        # No arm64 Windows official target yet; fall back to x86_64.
        return "x86_64-pc-windows-msvc"
    }
    return "x86_64-pc-windows-msvc"
}

function Get-InstallDir {
    if ($env:DS_INSTALL_DIR) {
        return $env:DS_INSTALL_DIR
    }
    $homeLocal = Join-Path $HOME ".local\bin"
    if (-not (Test-Path $homeLocal)) {
        New-Item -ItemType Directory -Path $homeLocal -Force | Out-Null
    }
    return $homeLocal
}

function Get-Sha256 {
    param([string]$Path)
    $hash = Get-FileHash -Algorithm SHA256 -Path $Path
    return $hash.Hash.ToLower()
}

# ---------- prebuilt-binary install path ----------

function Install-Prebuilt {
    $target = Get-Target
    if (-not $target) { return $false }

    Write-Log "detected target: $target"

    if (-not $Version) {
        Write-Log "resolving latest release tag from $Repo"
        $latestUrl = "https://github.com/$Repo/releases/latest"
        try {
            $resp = Invoke-WebRequest -Uri $latestUrl -Method Head -MaximumRedirection 0 -ErrorAction Stop
        } catch {
            try {
                $resp = Invoke-WebRequest -Uri $latestUrl -Method Head -ErrorAction Stop
            } catch {
                Write-Err "could not determine latest version: $($_.Exception.Message)"
                return $false
            }
        }
        # The final URL after redirect is in the 'Location' header.
        $final = $resp.Headers.Location
        if (-not $final) {
            # PowerShell may have followed the redirect already.
            $final = $resp.ResponseUri.ToString()
        }
        if ($final -match "/tag/([^/?#]+)") {
            $Version = $Matches[1]
        } else {
            Write-Err "could not extract version from $final"
            return $false
        }
        Write-Log "latest version: $Version"
    }

    $archive = "ds-$target.zip"
    $baseUrl = "https://github.com/$Repo/releases/download/$Version"
    $archiveUrl = "$baseUrl/$archive"
    $checksumsUrl = "$baseUrl/SHASUMS256.txt"

    $workdir = Join-Path ([System.IO.Path]::GetTempPath()) ("ds-install-" + [System.Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $workdir -Force | Out-Null

    try {
        Write-Log "downloading $archive"
        $archivePath = Join-Path $workdir $archive
        try {
            Invoke-WebRequest -Uri $archiveUrl -OutFile $archivePath -UseBasicParsing
        } catch {
            Write-Err "download failed: $archiveUrl"
            return $false
        }

        if (-not $SkipChecksum) {
            Write-Log "verifying checksum"
            $checksumsPath = Join-Path $workdir "SHASUMS256.txt"
            try {
                Invoke-WebRequest -Uri $checksumsUrl -OutFile $checksumsPath -UseBasicParsing
            } catch {
                Write-Err "could not download SHASUMS256.txt"
                return $false
            }
            $expected = $null
            Get-Content $checksumsPath | ForEach-Object {
                if ($_ -match "^\s*([a-fA-F0-9]{64})\s+\*?$([Regex]::Escape($archive))\s*$") {
                    $script:expected = $Matches[1].ToLower()
                }
            }
            if (-not $expected) {
                Write-Err "no checksum entry for $archive in SHASUMS256.txt"
                return $false
            }
            $actual = Get-Sha256 $archivePath
            if ($expected -ne $actual) {
                Write-Err "checksum mismatch!"
                Write-Err "  expected: $expected"
                Write-Err "  actual:   $actual"
                return $false
            }
            Write-Log "checksum OK"
        } else {
            Write-Log "skipping checksum verification (DS_SKIP_CHECKSUM=1)"
        }

        Write-Log "extracting"
        $extractDir = Join-Path $workdir "extract"
        New-Item -ItemType Directory -Path $extractDir -Force | Out-Null
        Expand-Archive -LiteralPath $archivePath -DestinationPath $extractDir -Force

        $binPath = Join-Path $extractDir "ds-$target\ds.exe"
        if (-not (Test-Path $binPath)) {
            Write-Err "extracted binary not found at $binPath"
            return $false
        }

        $dest = Get-InstallDir
        if (-not (Test-Path $dest)) {
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
        }
        $destBin = Join-Path $dest "ds.exe"
        Write-Log "installing to $destBin"
        Copy-Item -Path $binPath -Destination $destBin -Force

        Print-Done $destBin
        return $true
    } finally {
        Remove-Item -Recurse -Force $workdir -ErrorAction SilentlyContinue
    }
}

# ---------- source-build fallback path ----------

function Install-FromSource {
    Write-Log "building from source"

    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Write-Log "cargo not found; installing rustup (minimal profile)"
        if (-not (Get-Command curl -ErrorAction SilentlyContinue)) {
            Write-Err "curl is required to install rustup"
            return $false
        }
        try {
            Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile "$env:TEMP\rustup-init.exe" -UseBasicParsing
        } catch {
            Write-Err "failed to download rustup-init: $($_.Exception.Message)"
            return $false
        }
        $proc = Start-Process -FilePath "$env:TEMP\rustup-init.exe" -ArgumentList "-y","--profile","minimal" -NoNewWindow -Wait -PassThru
        if ($proc.ExitCode -ne 0) {
            Write-Err "rustup init failed with exit code $($proc.ExitCode)"
            return $false
        }
        # Make cargo available in the current session.
        $env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
    }

    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Write-Err "still no cargo after rustup install"
        return $false
    }

    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    if (-not (Test-Path (Join-Path $scriptDir "Cargo.toml"))) {
        Write-Err "no Cargo.toml at $scriptDir — run install.ps1 from a ds checkout"
        return $false
    }

    Write-Log "running cargo install --path $scriptDir --locked"
    Push-Location $scriptDir
    try {
        & cargo install --path $scriptDir --locked
    } finally {
        Pop-Location
    }

    $cargoBin = Join-Path $env:USERPROFILE ".cargo\bin\ds.exe"
    if (-not (Test-Path $cargoBin)) {
        Write-Err "cargo install succeeded but $cargoBin not found"
        return $false
    }

    Print-Done $cargoBin
    return $true
}

# ---------- finish ----------

function Print-Done {
    param([string]$Dest)
    Write-Log "installed: $Dest"
    $destDir = Split-Path -Parent $Dest
    if ($env:Path -like "*$destDir*") {
        Write-Log "verify: ds --version"
        try {
            & $Dest --version 2>$null | Out-Null
        } catch {}
    } else {
        Write-Log "NOTE: $destDir is not on your PATH"
        Write-Log "add it with:  `$env:Path = '$destDir;' + `$env:Path"
    }
}

# ---------- main ----------

if ($FromSource) {
    if (-not (Install-FromSource)) {
        exit 1
    }
} else {
    if (-not (Install-Prebuilt)) {
        Write-Log "prebuilt install failed; falling back to source build"
        if (-not (Install-FromSource)) {
            exit 1
        }
    }
}
