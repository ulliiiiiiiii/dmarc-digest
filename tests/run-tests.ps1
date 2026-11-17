#requires -Version 7.0
# Runs without extra modules: pwsh ./tests/run-tests.ps1
$ErrorActionPreference = 'Stop'
$tool = Join-Path $PSScriptRoot '..' 'dmarc-digest.ps1'
$script:failures = 0

function Assert-True {
    param([bool] $Condition, [string] $Message)
    if ($Condition) { Write-Host "ok    $Message" }
    else { Write-Host "FAIL  $Message"; $script:failures++ }
}

function New-Report {
    # Builds an aggregate report for example.org, 2026-11-01 (UTC).
    param([string] $Org, [object[]] $Rows)
    $records = foreach ($r in $Rows) {
        @"
  <record>
    <row>
      <source_ip>$($r.Ip)</source_ip>
      <count>$($r.Count)</count>
      <policy_evaluated><disposition>none</disposition><dkim>$($r.Dkim)</dkim><spf>$($r.Spf)</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.org</header_from></identifiers>
    <auth_results><spf><domain>example.org</domain><result>$($r.Spf)</result></spf></auth_results>
  </record>
"@
    }
    @"
<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>$Org</org_name><email>noreply@$Org</email><report_id>$Org-1</report_id>
    <date_range><begin>1793491200</begin><end>1793577599</end></date_range>
  </report_metadata>
  <policy_published><domain>example.org</domain><p>none</p><pct>100</pct></policy_published>
$($records -join "`n")
</feedback>
"@
}

function Write-GzipFile {
    param([string] $File, [string] $Text)
    $out = [System.IO.File]::Create($File)
    $gzip = [System.IO.Compression.GZipStream]::new($out, [System.IO.Compression.CompressionMode]::Compress)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $gzip.Write($bytes, 0, $bytes.Length)
    $gzip.Dispose()
}

function Write-ZipFile {
    param([string] $File, [string] $EntryName, [string] $Text)
    $zip = [System.IO.Compression.ZipFile]::Open($File, [System.IO.Compression.ZipArchiveMode]::Create)
    $writer = [System.IO.StreamWriter]::new($zip.CreateEntry($EntryName).Open())
    $writer.Write($Text)
    $writer.Dispose()
    $zip.Dispose()
}

function Invoke-Tool {
    # Runs the tool like a user would and returns its exit status.
    param([string[]] $Arguments)
    $null = & pwsh -NoProfile -File $tool @Arguments 2>&1
    $LASTEXITCODE
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) "dmarc-digest-tests-$PID"
$mixed = Join-Path $work 'mixed'
$clean = Join-Path $work 'clean'
New-Item -ItemType Directory -Path $mixed, $clean -Force | Out-Null

try {
    # One plain, one gzipped and one zipped report; one sender fails.
    Set-Content -LiteralPath (Join-Path $mixed 'a.xml') -Encoding utf8 -Value (New-Report 'mail.example' @(
            @{ Ip = '192.0.2.10'; Count = 5; Dkim = 'pass'; Spf = 'pass' },
            @{ Ip = '198.51.100.7'; Count = 3; Dkim = 'fail'; Spf = 'fail' }))
    Write-GzipFile (Join-Path $mixed 'b.xml.gz') (New-Report 'other.example' @(
            @{ Ip = '192.0.2.10'; Count = 2; Dkim = 'pass'; Spf = 'fail' }))
    Write-ZipFile (Join-Path $mixed 'c.zip') 'c.xml' (New-Report 'third.example' @(
            @{ Ip = '203.0.113.5'; Count = 4; Dkim = 'fail'; Spf = 'pass' }))
    Set-Content -LiteralPath (Join-Path $mixed 'broken.xml') -Value '<html><body>not a report</body></html>'

    $records = @(& $tool -Path $mixed -Raw -WarningAction SilentlyContinue)
    Assert-True ($records.Count -eq 4) 'reads xml, gz and zip and skips a file that is no report'
    Assert-True (@($records | Where-Object Dmarc -EQ 'fail').Count -eq 1) 'marks only the record without SPF or DKIM pass as fail'
    Assert-True (($records | Where-Object SourceIp -EQ '203.0.113.5').Dmarc -eq 'pass') 'SPF pass alone is enough for DMARC'
    Assert-True ($records[0].Begin -eq [datetime]'2026-11-01') 'reads the report period'

    $csv = Join-Path $work 'digest.csv'
    $status = Invoke-Tool @('-Path', $mixed, '-CsvPath', $csv)
    Assert-True ($status -eq 2) 'exit status 2 when messages fail'
    $rows = @(Import-Csv -LiteralPath $csv)
    Assert-True ($rows.Count -eq 3) 'one summary row per sender'
    Assert-True ($rows[0].SourceIp -eq '198.51.100.7' -and $rows[0].Failed -eq '3') 'failing sender comes first'
    $repeat = $rows | Where-Object SourceIp -EQ '192.0.2.10'
    Assert-True ($repeat.Messages -eq '7' -and $repeat.Passed -eq '7') 'adds up one sender across reports'

    Set-Content -LiteralPath (Join-Path $clean 'ok.xml') -Encoding utf8 -Value (New-Report 'mail.example' @(
            @{ Ip = '192.0.2.10'; Count = 9; Dkim = 'pass'; Spf = 'pass' }))
    Assert-True ((Invoke-Tool @('-Path', $clean)) -eq 0) 'exit status 0 when every message passed'

    $empty = Join-Path $work 'empty'
    New-Item -ItemType Directory -Path $empty | Out-Null
    Assert-True ((Invoke-Tool @('-Path', $empty)) -eq 1) 'exit status 1 when there is no report'
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

if ($script:failures -gt 0) {
    Write-Host "$($script:failures) test(s) failed"
    exit 1
}
Write-Host 'all tests passed'
exit 0
