# This file is part of Yeah! Torta.
# SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
# Copyright 2026 Saimonokuma.
#
# avd-guard.ps1 - launch a Torta AVD with an IDLE AUTO-SHUTDOWN that saves the session.
#
# WHY: an emulator left running while nobody is driving it burns CPU and RAM for nothing.
# This wraps the launch so the AVD closes itself after -IdleSeconds (default 300) with no
# activity, and closes it the way that PRESERVES state: `adb emu kill` performs a graceful
# shutdown, which writes the Quick Boot snapshot. A hard process kill would lose the session,
# so this script never does that to the emulator.
#
# HOW IDLENESS IS MEASURED - two independent signals, whichever is more recent wins:
#   1. THE HEARTBEAT. Every adb command issued through `tools/tadb` touches a beat file.
#      This covers agent-driven use, which is the case that was actually wasting resources.
#   2. DEVICE-SIDE USER ACTIVITY. `dumpsys power` reports when the screen was last touched,
#      which covers a human clicking in the emulator window while no adb traffic flows.
#      The parser is BEST-EFFORT: Android has changed this field's format across versions, so
#      when it cannot be parsed the script SAYS SO in the log and falls back to signal 1 alone
#      rather than silently pretending it has a reading it does not have.
#
# SAFETY - the process-handling rules this repo works under:
#   * Every process is tracked by EXACT PID in a pid file under .avd-guard/. Nothing here ever
#     kills by name or pattern; a pattern kill on this machine can take down unrelated
#     processes, including the local proxy on 127.0.0.1:5588 that carries API traffic.
#   * Stopping is always `adb emu kill` (graceful, saves the snapshot). Stop-Process is used
#     ONLY on this script's own watchdog, and only by its recorded PID.
#
# USAGE
#   powershell -NoProfile -File tools/avd-guard.ps1 -Action launch            # start + guard
#   powershell -NoProfile -File tools/avd-guard.ps1 -Action launch -IdleSeconds 20   # test it
#   powershell -NoProfile -File tools/avd-guard.ps1 -Action beat              # mark as used
#   powershell -NoProfile -File tools/avd-guard.ps1 -Action status            # idle seconds
#   powershell -NoProfile -File tools/avd-guard.ps1 -Action stop              # save + close now
#   powershell -NoProfile -File tools/avd-guard.ps1 -Action watch             # (internal)

[CmdletBinding()]
param(
    [ValidateSet('launch', 'watch', 'beat', 'status', 'stop')]
    [string]$Action = 'launch',
    [string]$Avd = 'torta_fresh',
    [int]$IdleSeconds = 300,
    [int]$PollSeconds = 10,
    [string]$Sdk = 'D:/android-sdk'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Emulator = Join-Path $Sdk 'emulator/emulator.exe'
$Adb = Join-Path $Sdk 'platform-tools/adb.exe'
$GuardDir = Join-Path $PSScriptRoot '../.avd-guard'
$BeatFile = Join-Path $GuardDir 'beat'
$LogFile = Join-Path $GuardDir 'guard.log'
$EmuPid = Join-Path $GuardDir 'emulator.pid'
$WatchPid = Join-Path $GuardDir 'watchdog.pid'

function Ensure-GuardDir {
    if (-not (Test-Path $GuardDir)) { New-Item -ItemType Directory -Path $GuardDir -Force | Out-Null }
}

# ASCII only, explicit UTF-8, explicit LF. A non-ASCII character here can raise mid-script on a
# Windows console and leave the guard half-started while the traceback suggests nothing happened.
function Write-Log([string]$Message) {
    Ensure-GuardDir
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[$stamp] $Message"
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
    Write-Output $line
}

function Touch-Beat {
    Ensure-GuardDir
    Set-Content -Path $BeatFile -Value (Get-Date).Ticks -Encoding UTF8 -NoNewline
}

function Get-BeatIdleSeconds {
    if (-not (Test-Path $BeatFile)) { return [int]::MaxValue }
    return [int]((Get-Date) - (Get-Item $BeatFile).LastWriteTime).TotalSeconds
}

# Best-effort read of the device's own last-touch time. Returns $null when it cannot be
# established - the caller must treat $null as "no reading", never as "idle".
function Get-DeviceIdleSeconds {
    try {
        $state = (& $Adb get-state 2>$null | Out-String).Trim()
        if ($state -ne 'device') { return $null }
        $power = (& $Adb shell dumpsys power 2>$null | Out-String)
        if ([string]::IsNullOrWhiteSpace($power)) { return $null }

        # PREFERRED form, measured on this AVD (SDK 34):
        #     lastUserActivityTime=21619 (43939 ms ago)
        # It states the elapsed time directly, so no uptime arithmetic and no clock skew.
        # This is checked FIRST because the sibling field on the same image is printed as
        #     mLastUserActivityTime(excludingAttention)=21619
        # whose parenthetical sits between the name and the '=' - a regex anchored on
        # "mLastUserActivityTime=" matches NEITHER line, which is exactly why the first
        # version of this function reported "unavailable" on a device that had the data.
        $ago = [regex]::Match($power, 'lastUserActivityTime\s*=\s*-?\d+\s*\((\d+)\s*ms ago\)')
        if ($ago.Success) {
            return [int]([int64]$ago.Groups[1].Value / 1000)
        }

        # FALLBACK for images that print only an absolute uptime-millis value.
        $m = [regex]::Match($power, 'mLastUserActivityTime(?:\([^)]*\))?\s*=\s*(-?\d+)')
        if ($m.Success) {
            $lastMs = [int64]$m.Groups[1].Value
            if ($lastMs -lt 0) { return $null }
            $up = (& $Adb shell cat /proc/uptime 2>$null | Out-String).Trim()
            $upSecs = [double](($up -split '\s+')[0])
            $upMs = [int64]($upSecs * 1000)
            $delta = [int](($upMs - $lastMs) / 1000)
            if ($delta -lt 0) { return $null }
            return $delta
        }
        return $null
    } catch {
        return $null
    }
}

switch ($Action) {

    'beat' { Touch-Beat }

    'status' {
        $b = Get-BeatIdleSeconds
        $d = Get-DeviceIdleSeconds
        $dText = if ($null -eq $d) { 'unavailable' } else { "$d s" }
        Write-Output "beat idle: $b s | device idle: $dText | threshold: $IdleSeconds s"
    }

    'stop' {
        # Graceful ONLY - this is what writes the Quick Boot snapshot.
        Write-Log "stop requested - graceful 'adb emu kill' (saves the session)"
        & $Adb emu kill 2>&1 | Out-Null
        Start-Sleep -Seconds 3
        Write-Log "stop complete"
    }

    'launch' {
        Ensure-GuardDir
        Touch-Beat

        # NOTE: no -no-snapshot-save and no -no-snapshot-load. Quick Boot therefore RESTORES the
        # previous session on start and SAVES it on graceful exit, which is the behaviour asked
        # for. -no-boot-anim only trims startup cost; it does not affect snapshotting.
        $emuArgs = @('-avd', $Avd, '-no-boot-anim')
        $p = Start-Process -FilePath $Emulator -ArgumentList $emuArgs -PassThru -WindowStyle Minimized
        Set-Content -Path $EmuPid -Value $p.Id -Encoding UTF8 -NoNewline
        Write-Log "launched AVD '$Avd' as PID $($p.Id) (quick-boot save+load enabled)"

        # Start-Process does NOT quote the members of -ArgumentList. This repo lives at
        # "C:\GIT External Repo\Yeah!Torta-Universal-x86_64\...", so an unquoted $PSCommandPath is
        # split at the first space and powershell receives -File 'C:\GIT' - which it rejects with
        # "Il file non ha estensione 'ps1'". The first version of this script did exactly that, so
        # the watchdog died instantly at every launch while the log still said "armed". Anything
        # that can contain a space is quoted here.
        $q = { param($s) '"' + $s + '"' }
        $watchArgs = @(
            '-NoProfile', '-WindowStyle', 'Hidden', '-File', (& $q $PSCommandPath),
            '-Action', 'watch', '-Avd', (& $q $Avd),
            '-IdleSeconds', $IdleSeconds, '-PollSeconds', $PollSeconds, '-Sdk', (& $q $Sdk)
        )
        $w = Start-Process -FilePath 'powershell' -ArgumentList $watchArgs -PassThru -WindowStyle Hidden
        Set-Content -Path $WatchPid -Value $w.Id -Encoding UTF8 -NoNewline

        # VERIFY THE WATCHDOG IS REALLY UP before claiming it is armed. The failure above was
        # silent and self-congratulating: the log announced a guarded emulator that nothing was
        # guarding, and the AVD then sat idle for 700+ seconds under a "300s" threshold. A guard
        # that cannot tell "armed" from "died on startup" is worse than no guard, because it is
        # trusted. Two independent checks: the process exists, and it wrote its own start line.
        Start-Sleep -Seconds 3
        $alive = $null -ne (Get-Process -Id $w.Id -ErrorAction SilentlyContinue)
        # @(...) forces an array. Under Set-StrictMode a pipeline that matches zero lines yields
        # $null and one that matches a single line yields a scalar - neither has a .Count, and the
        # check then THROWS instead of answering. That happened once here: the arming verification
        # itself failed with PropertyNotFoundStrict. A check that can throw is not a check.
        $logged = (Test-Path $LogFile) -and
                  (@(Get-Content $LogFile -Tail 5 | Where-Object { $_ -match 'watchdog start' }).Count -gt 0)
        if ($alive -and $logged) {
            Write-Log "watchdog PID $($w.Id) ARMED and confirmed - idle ${IdleSeconds}s, poll ${PollSeconds}s"
            Write-Output "AVD_PID=$($p.Id) WATCHDOG_PID=$($w.Id) IDLE_SECONDS=$IdleSeconds WATCHDOG=CONFIRMED"
        } else {
            Write-Log "WATCHDOG FAILED TO START (alive=$alive logged=$logged) - the AVD is NOT guarded"
            Write-Output "AVD_PID=$($p.Id) WATCHDOG=FAILED - the AVD is running UNGUARDED"
            exit 3
        }
    }

    'watch' {
        Write-Log "watchdog start (threshold ${IdleSeconds}s, poll ${PollSeconds}s)"
        $warnedAboutParse = $false
        while ($true) {
            Start-Sleep -Seconds $PollSeconds

            $state = (& $Adb get-state 2>$null | Out-String).Trim()
            if ($state -ne 'device') {
                Write-Log "no device attached - watchdog exiting (nothing left to guard)"
                break
            }

            $beatIdle = Get-BeatIdleSeconds
            $devIdle = Get-DeviceIdleSeconds
            if ($null -eq $devIdle -and -not $warnedAboutParse) {
                Write-Log "device-side idle signal UNAVAILABLE on this image - falling back to the heartbeat alone"
                $warnedAboutParse = $true
            }

            # The most recent activity of either signal defines idleness. Using the MINIMUM is
            # the conservative choice: a reading that says "used 2s ago" must never be overruled
            # by a stale one that says "idle 400s".
            $idle = $beatIdle
            if ($null -ne $devIdle -and $devIdle -lt $idle) { $idle = $devIdle }

            if ($idle -ge $IdleSeconds) {
                Write-Log "idle ${idle}s >= ${IdleSeconds}s - saving session and closing the AVD"
                & $Adb emu kill 2>&1 | Out-Null
                Start-Sleep -Seconds 5
                Write-Log "AVD closed by idle timer (session saved via quick boot)"
                break
            }
        }
        Write-Log "watchdog end"
    }
}
