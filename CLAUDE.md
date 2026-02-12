# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

InSpec compliance profile implementing the **CIS Oracle Cloud Infrastructure Foundations Benchmark v3.0.0**. Maintained by the MITRE SAF Team. Uses CINC-Auditor (open-source Chef InSpec) to automate security compliance validation against OCI tenancies.

- Profile: `cis-oracle-cloud-infrastructure-foundations-benchmark-v3.0.0`
- Version: 3.0.1
- License: Apache-2.0

## Commands

```bash
# Install dependencies
bundle install

# Validate the InSpec profile (syntax/structure check)
bundle exec rake inspec:check

# Lint with RuboCop
bundle exec rake lint
bundle exec rake lint:auto_correct

# Run both lint and profile validation
bundle exec rake pre_commit_checks

# Format control files for readability (heredocs, word wrap at 90 chars)
ruby format_controls.rb                    # All controls in controls/
ruby format_controls.rb controls/1_4.rb    # Single file

# Run profile against a target
bundle exec cinc-auditor exec . -t ssh://<host>:<port> --sudo --input-file=inputs.yml --reporter=cli json:results.json
```

## Architecture

### Control Files (`controls/`)

54 Ruby files, one per CIS benchmark requirement. Organized by CIS section:

| Section | Files | Domain |
|---------|-------|--------|
| 1_x | 1_1 - 1_17 | IAM |
| 2_x | 2_1 - 2_8 | Logging & Monitoring |
| 3_x | 3_1 - 3_3 | Networking |
| 4_x | 4_1 - 4_18 | Infrastructure |
| 5_x_x | 5_1_1 - 5_3_1 | Storage |
| 6_x | 6_1 - 6_2 | Database |

**Currently stubs only** — controls contain metadata (title, descriptions, tags, impact) but no `describe` blocks with actual InSpec resource checks yet.

### Control File Format

Each control follows this structure after formatting:

```ruby
control '1_4' do
  title 'Ensure IAM password policy requires minimum length of 14 or greater'

  desc <<~DESC
    Description of the requirement...
  DESC

  desc 'check', <<~CHECK
    Verification procedures (console and CLI)...
  CHECK

  desc 'fix', <<~FIX
    Remediation steps...
  FIX

  impact 0.5

  tag check_id: 'C-1_4'
  tag severity: 'medium'
  tag gid: 'CIS-1_4'
  tag rid: 'xccdf_cis_cis_rule_1_4'
  tag stig_id: '1.4'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag 'documentable'

  tag cci: %w[CCI-000364 CCI-000365 ...]
  tag nist: ['CM-6 a', 'CM-6 b', ...]
end
```

### Key Conventions

- Use heredocs (`<<~DESC`, `<<~CHECK`, `<<~FIX`) for multi-line descriptions
- Wrap text at 90 characters
- Use `%w[]` for CCI arrays (single words), regular arrays for NIST tags (contain spaces)
- Single quotes for strings unless interpolation needed
- `format_controls.rb` handles reformatting — run it after bulk edits

### Inputs (`inspec.yml`)

Profile inputs are defined in `inspec.yml`. Do not modify defaults directly — use override files:

```bash
cinc-auditor exec . --input-file=my_inputs.yml
cinc-auditor exec . --input disable_slow_controls=true
```

### Results Viewing

JSON output can be loaded into [Heimdall-Lite](https://heimdall-lite.mitre.org/) or exported as DISA Checklist (CKL) for eMass upload via the SAF CLI.
