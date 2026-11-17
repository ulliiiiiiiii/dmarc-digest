#requires -Version 7.0
<#
.SYNOPSIS
    Turns DMARC aggregate reports into one readable table.

.DESCRIPTION
    Reads DMARC aggregate reports (RFC 7489) as .xml, .gz or .zip files, from single files or whole folders,
    and shows which servers send mail in the domain's name and whether that mail passes DMARC. A message
    passes when SPF or DKIM passes and matches the From domain. The reports already contain that result in
    policy_evaluated; this script adds it up per sending server.

    Exit status: 0 when every message passed, 2 when some failed, 1 when no report could be read.

.EXAMPLE
    ./dmarc-digest.ps1 -Path ./reports

.EXAMPLE
    ./dmarc-digest.ps1 -Path ./reports -ResolveNames -CsvPath digest.csv

.EXAMPLE
    ./dmarc-digest.ps1 -Path ./reports -Raw | Where-Object Dmarc -eq 'fail'
#>
[CmdletBinding()]
param(
    # Report files or folders. Folders are searched recursively.
    [Parameter(Mandatory, Position = 0)]
    [string[]] $Path,

    # Look up the host name of every sending IP address (reverse DNS).
    [switch] $ResolveNames,

    # Also save the summary table as CSV.
    [string] $CsvPath,

    # Output one object per report record instead of the summary.
    [switch] $Raw
)

$ErrorActionPreference = 'Stop'

function Get-ReportFile {
    param([string[]] $Path)
    foreach ($item in $Path) {
        if (Test-Path -LiteralPath $item -PathType Container) {
            Get-ChildItem -LiteralPath $item -File -Recurse | Where-Object Name -Match '\.(xml|gz|zip)$'
        } elseif (Test-Path -LiteralPath $item -PathType Leaf) {
            Get-Item -LiteralPath $item
        } else {
            throw "Not found: $item"
        }
    }
}

function Read-ReportText {
    # Returns the XML text of every report inside one file.
    param([System.IO.FileInfo] $File)
    if ($File.Name -match '\.zip$') {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($File.FullName)
        try {
            foreach ($entry in $zip.Entries | Where-Object Name -Match '\.xml$') {
                $reader = [System.IO.StreamReader]::new($entry.Open())
                try { $reader.ReadToEnd() } finally { $reader.Dispose() }
            }
        } finally { $zip.Dispose() }
    } elseif ($File.Name -match '\.gz$') {
        $gzip = [System.IO.Compression.GZipStream]::new([System.IO.File]::OpenRead($File.FullName),
            [System.IO.Compression.CompressionMode]::Decompress)
        $reader = [System.IO.StreamReader]::new($gzip)
        try { $reader.ReadToEnd() } finally { $reader.Dispose() }
    } else {
        [System.IO.File]::ReadAllText($File.FullName)
    }
}

function ConvertFrom-DmarcReport {
    param([string] $Text)
    $doc = [xml] $Text
    $feedback = $doc.feedback
    if (-not $feedback -or -not $feedback.report_metadata) { throw 'not a DMARC aggregate report' }
    $meta = $feedback.report_metadata
    $begin = [DateTimeOffset]::FromUnixTimeSeconds([long] $meta.date_range.begin).UtcDateTime
    $end = [DateTimeOffset]::FromUnixTimeSeconds([long] $meta.date_range.end).UtcDateTime
    foreach ($record in @($feedback.record)) {
        $evaluated = $record.row.policy_evaluated
        [pscustomobject]@{
            Domain      = $feedback.policy_published.domain
            Reporter    = $meta.org_name
            Begin       = $begin
            End         = $end
            SourceIp    = $record.row.source_ip
            Count       = [int] $record.row.count
            HeaderFrom  = $record.identifiers.header_from
            Spf         = $evaluated.spf
            Dkim        = $evaluated.dkim
            Disposition = $evaluated.disposition
            Dmarc       = if ($evaluated.dkim -eq 'pass' -or $evaluated.spf -eq 'pass') { 'pass' } else { 'fail' }
        }
    }
}

$hostNames = @{}
function Resolve-HostName {
    param([string] $Ip)
    if (-not $hostNames.ContainsKey($Ip)) {
        $hostNames[$Ip] = try { [System.Net.Dns]::GetHostEntry($Ip).HostName } catch { '' }
    }
    $hostNames[$Ip]
}

$reports = 0
$records = @(foreach ($file in Get-ReportFile -Path $Path) {
        foreach ($text in Read-ReportText -File $file) {
            try {
                ConvertFrom-DmarcReport -Text $text
                $reports++
            } catch {
                Write-Warning "Skipped $($file.Name): $($_.Exception.Message)"
            }
        }
    })

if ($records.Count -eq 0) {
    Write-Warning 'No DMARC records found.'
    exit 1
}

if ($Raw) {
    $records
    return
}

$summary = @($records | Group-Object SourceIp, HeaderFrom | ForEach-Object {
        $group = $_.Group
        $messages = [int] ($group | Measure-Object Count -Sum).Sum
        $passed = [int] ($group | Where-Object Dmarc -EQ 'pass' | Measure-Object Count -Sum).Sum
        $row = [ordered]@{ SourceIp = $group[0].SourceIp }
        if ($ResolveNames) { $row.HostName = Resolve-HostName $group[0].SourceIp }
        $row.HeaderFrom = $group[0].HeaderFrom
        $row.Messages = $messages
        $row.Passed = $passed
        $row.Failed = $messages - $passed
        [pscustomobject] $row
    } | Sort-Object -Property @{ Expression = 'Failed'; Descending = $true }, @{ Expression = 'Messages'; Descending = $true })

if ($CsvPath) {
    $summary | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding utf8
}

$first = ($records | Measure-Object Begin -Minimum).Minimum
$last = ($records | Measure-Object End -Maximum).Maximum
$total = [int] ($summary | Measure-Object Messages -Sum).Sum
$failed = [int] ($summary | Measure-Object Failed -Sum).Sum
$failingSources = @($summary | Where-Object Failed -GT 0).Count

$summary | Format-Table -AutoSize | Out-Host
Write-Host ('{0} reports from {1:yyyy-MM-dd} to {2:yyyy-MM-dd} (UTC), {3} messages.' -f $reports, $first, $last, $total)
if ($failed -eq 0) {
    Write-Host 'Every message passed DMARC.'
    exit 0
}
$sources = if ($failingSources -eq 1) { '1 source' } else { "$failingSources sources" }
Write-Host "$failed of $total messages failed DMARC, from $sources."
Write-Host 'If none of these sources sends mail for you, p=quarantine is safe.'
exit 2
