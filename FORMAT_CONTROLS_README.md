# Control File Formatter

This script reformats InSpec control files for better readability while maintaining valid Ruby syntax.

## Features

- **Smart skip detection** - Automatically skips already-formatted files
- Converts long single-line strings to readable heredoc format (`<<~DESC`)
- Wraps text at 90 characters for better readability
- Formats arrays (cci, nist) with one item per line
- Standardizes quote style to single quotes
- Maintains proper indentation
- Adds blank lines between logical sections
- Preserves all control metadata and tags
- Provides summary statistics (formatted/skipped/errors)

## Usage

```bash
# Format a single control file
ruby format_controls.rb controls/1_1.rb

# Format all files in controls directory
ruby format_controls.rb controls/

# Format all files in current directory's controls/ (default)
ruby format_controls.rb
```

## What Gets Formatted

### Before:
```ruby
control "1_2" do
  title "Ensure permissions on all resources are given only to the tenancy administrator group"
  desc "There is a built-in OCI IAM policy enabling the Administrators group to perform any action within a tenancy. In the OCI IAM console, this policy reads: Allow group Administrators to manage all-resources in tenancy..."
  desc "check", 'From CLI: Run OCI CLI command providing the root compartment OCID...'
  desc "fix", "From Console: Login to OCI console. Go to Identity -> Policies..."
  impact 0.5
  tag check_id: "C-1_2"
  tag cci: ["CCI-000213", "CCI-000225", "CCI-000036"]
  tag nist: ["AC-3", "AC-6", "AC-5 a"]
end
```

### After:
```ruby
control '1_2' do
  title 'Ensure permissions on all resources are given only to the tenancy administrator group'

  desc <<~DESC
    There is a built-in OCI IAM policy enabling the Administrators group to perform any
    action within a tenancy. In the OCI IAM console, this policy reads: Allow group
    Administrators to manage all-resources in tenancy...
  DESC

  desc 'check', <<~CHECK
    From CLI:
    Run OCI CLI command providing the root compartment OCID...
  CHECK

  desc 'fix', <<~FIX
    From Console:
    Login to OCI console. Go to Identity -> Policies...
  FIX

  impact 0.5

  tag check_id: 'C-1_2'
  tag severity: 'medium'
  tag gid: 'CIS-1_2'

  tag cci: [
    'CCI-000213',
    'CCI-000225',
    'CCI-000036'
  ]

  tag nist: [
    'AC-3',
    'AC-6',
    'AC-5 a'
  ]
end
```

## How Skip Detection Works

The script detects already-formatted files by checking for:

1. **Heredoc syntax** - Presence of `<<~DESC`, `<<~CHECK`, or `<<~FIX`
2. **Multi-line arrays** - Formatted cci or nist tag arrays with newlines

If either pattern is found, the file is skipped to avoid unnecessary rewrites.

## Output

The script provides real-time feedback:

```
Found 54 control files

⊘ Skipped (already formatted): controls/1_1.rb
✓ Formatted: controls/1_2.rb
✓ Formatted: controls/1_3.rb
...

============================================================
Summary:
  ✓ Formatted: 51 files
  ⊘ Skipped:   3 files (already formatted)
============================================================
```

## Backup Recommendation

While the script modifies files in-place, it's recommended to:

1. Use version control (git) before running
2. Run on a single file first to verify output
3. Review changes with `git diff` before committing
4. The script is idempotent - safe to run multiple times

## Validation

After formatting, you can validate the controls still work:

```bash
# Run InSpec to verify syntax
inspec check .

# Run specific control
inspec exec . --controls 1_1
```

## Notes

- The script preserves all control logic and metadata
- It only reformats for readability
- Output is still valid Ruby and InSpec code
- Some RuboCop warnings (block length, word array) are normal for InSpec controls
