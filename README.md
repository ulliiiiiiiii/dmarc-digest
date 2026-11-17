# dmarc-digest

A DMARC record with `p=none` only collects reports. The big mail providers send them every day as XML,
mostly zipped, and they tend to pile up unread. Yet they hold the one answer you need before switching to
`p=quarantine`: does every server that sends mail in your name pass DMARC?

dmarc-digest reads a folder of these aggregate reports and answers that in one table. It handles `.xml`,
`.gz` and `.zip` files and needs nothing but PowerShell 7, on Windows, macOS or Linux.

## Usage

```powershell
./dmarc-digest.ps1 -Path ./reports
./dmarc-digest.ps1 -Path ./reports -ResolveNames          # adds the host name of every sender
./dmarc-digest.ps1 -Path ./reports -CsvPath digest.csv    # also saves the table as CSV
./dmarc-digest.ps1 -Path ./reports -Raw | Where-Object Dmarc -eq fail
```

```text
SourceIp     HeaderFrom  Messages Passed Failed
--------     ----------  -------- ------ ------
198.51.100.7 example.org        3      0      3
192.0.2.10   example.org       58     58      0
203.0.113.5  example.org        6      6      0

3 reports from 2026-11-01 to 2026-11-01 (UTC), 67 messages.
3 of 67 messages failed DMARC, from 1 source.
If none of these sources sends mail for you, p=quarantine is safe.
```

Exit status: 0 when every message passed, 2 when some failed, 1 when no report could be read. That makes it
easy to run as a scheduled task and alert on 2.

## How it decides

A message passes DMARC when SPF or DKIM passes and matches the domain in the From header. The receiving
provider already writes that result into each report (`policy_evaluated`), so dmarc-digest does not guess: it
adds the results up per sending server and puts the failures on top.

## Tests

```powershell
./tests/run-tests.ps1
```

The tests build reports in all three formats and run the script the way a user would. They need no extra
modules.

## License

MIT
