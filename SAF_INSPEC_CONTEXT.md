# MITRE SAF InSpec Profile Development — LLM Context Reference

This file captures the patterns, conventions, and rationale behind how MITRE SAF writes InSpec profiles, distilled from the official SAF Training courses. Use this as authoritative context when developing or modifying controls in this profile.

---

## 1. What InSpec Is

InSpec is a Ruby-based DSL for compliance-as-code. It validates that systems meet security requirements by comparing actual vs. desired state. Key properties:

- **Read-only**: InSpec never modifies target systems. It validates; separate tools (Ansible, Chef, Terraform) remediate.
- **Agentless**: Installed on a "runner" host, routes commands to targets over SSH, WinRM, Docker API, Kubernetes API, etc.
- **CINC Auditor**: Open-source build of Chef InSpec (CINC-Is-Not-Chef). Functionally identical, no license required.
- **Built on RSpec**: InSpec extends RSpec with a resource library and human-friendly syntax.

Security guidance documents (STIGs, CIS Benchmarks) are the source of truth. InSpec profiles are the programmatic implementation of that same guidance.

---

## 2. Profile Structure

### Required
- `inspec.yml` — profile metadata (name, version, maintainer, inputs, depends)
- `controls/` — one `.rb` file per security requirement

### Optional
- `libraries/` — custom InSpec resources (Ruby classes)
- `files/` — supporting data files (YAML, JSON)
- `inputs.yml` — runtime input overrides
- `README.md`

### Validation
```sh
inspec check .                    # or: bundle exec cinc-auditor check .
bundle exec rake inspec:check     # via Rakefile
```

---

## 3. Control Writing

### Canonical Structure (in order)

```ruby
control 'CONTROL_ID' do
  title 'Short requirement statement'

  desc <<~DESC
    General description of the requirement...
  DESC

  desc 'check', <<~CHECK
    How to verify compliance (verbatim from guidance)...
  CHECK

  desc 'fix', <<~FIX
    How to remediate (verbatim from guidance)...
  FIX

  impact 0.5

  # Metadata tags
  tag check_id: 'C-1_4'
  tag severity: 'medium'
  tag gid: 'CIS-1_4'
  tag rid: 'xccdf_cis_cis_rule_1_4'
  tag stig_id: '1.4'
  tag gtitle: 'SRG mapping'
  tag 'documentable'
  tag cci: %w[CCI-000364 CCI-000365]
  tag nist: ['CM-6 a', 'CM-6 b']

  # Not Applicable / skip conditions (before describe blocks — fail fast)
  only_if('Control not applicable in containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  # Input variables
  min_length = input('password_min_length')

  # Test logic
  describe some_resource do
    its('attribute') { should cmp >= min_length }
  end
end
```

### Describe Block Fundamentals

```ruby
# Test the resource itself
describe file('/etc/config') do
  it { should exist }
  it { should be_file }
  it { should be_owned_by 'root' }
end

# Test resource attributes
describe nginx do
  its('version') { should cmp >= '1.27.0' }
  its('modules') { should include 'http_ssl' }
end

# Negation
it { should_not be_readable.by('others') }
it { should_not be_writable.by('others') }
```

### OR Logic (either condition acceptable)
```ruby
describe.one do
  describe file('/var/log/messages') do
    it { should be_owned_by 'root' }
  end
  describe file('/var/log/messages') do
    it { should_not exist }
  end
end
```

### Custom Failure Messages (expect syntax)
```ruby
bad_users = users.shells(/bash/).usernames - input('admin_users')
describe 'Shell access' do
  it 'should be restricted to admin users' do
    failure_message = "Non-admin users with shell access: #{bad_users.join(', ')}"
    expect(bad_users).to be_empty, failure_message
  end
end
```

### "Find the Outsiders" Pattern
For large datasets, search for violations instead of checking every item:
```ruby
bad_users = inspec.shadow.where { password != "*" && password != "!" && password !~ /\$6\$/ }.users
describe 'Password hashes' do
  it 'should only contain SHA512' do
    expect(bad_users).to be_empty, "Users without SHA512: #{bad_users.join(', ')}"
  end
end
```

### Using `subject` for Clean Output
Prevents raw command output from cluttering reports:
```ruby
describe 'Directory listing' do
  subject { command('ls -al /etc/nginx').stdout.strip }
  it { should_not be_empty }
end
```

---

## 4. Impact Levels

Maps to STIG severity / CIS importance:

| Impact | Severity | STIG CAT |
|--------|----------|----------|
| 0.0    | Not Applicable | N/A |
| 0.1–0.3 | low | CAT III |
| 0.4–0.6 | medium | CAT II |
| 0.7–1.0 | high | CAT I |

Standard values: `0.7` (high), `0.5` (medium), `0.3` (low), `0.0` (N/A).

---

## 5. Handling Different Check Types

### Automated
Standard `describe` blocks with resources and matchers.

### Manual / Not Reviewed
```ruby
describe 'Manual Review' do
  skip 'This control must be manually reviewed.'
end
```
Produces "Not Reviewed" (skipped) status. The requirement still needs manual assessment.

### Not Applicable (Dynamic)
```ruby
only_if('Not applicable to containers', impact: 0.0) {
  !virtualization.system.eql?('docker')
}
```
Place **before** describe blocks. When false, control is marked N/A with impact 0.0 and no tests execute.

---

## 6. Tagging Conventions

### Standard Tag Set (CIS profiles)
```ruby
tag check_id: 'C-1_4'                              # Check procedure ID
tag severity: 'medium'                               # low / medium / high
tag gid: 'CIS-1_4'                                  # Group ID
tag rid: 'xccdf_cis_cis_rule_1_4'                   # Rule ID
tag stig_id: '1.4'                                   # CIS section number
tag gtitle: '<GroupDescription></GroupDescription>'   # Group title
tag 'documentable'                                   # Documentable flag
tag cci: %w[CCI-000364 CCI-000365]                  # Control Correlation Identifiers
tag nist: ['CM-6 a', 'CM-6 b']                      # NIST 800-53 mappings
```

### Standard Tag Set (STIG profiles)
```ruby
tag check_id: 'C-61532r925358_chk'
tag severity: 'medium'
tag gid: 'V-257791'
tag rid: 'SV-257791r925360_rule'
tag stig_id: 'RHEL-09-212030'
tag gtitle: 'SRG-OS-000480-GPOS-00227'
tag fix_id: 'F-61456r925359_fix'
tag 'documentable'
tag cci: ['CCI-000366']
tag nist: ['CM-6 b']
tag 'host'
```

Tags are the reason Heimdall and other tools can sort and display results with high fidelity. They link each control back to the requirement it tests.

---

## 7. Input Patterns

### Defining in `inspec.yml`
```yaml
inputs:
  - name: password_min_length
    type: Numeric
    value: 14

  - name: admin_users
    type: Array
    value:
      - admin
```

Supported types: `String`, `Array`, `Numeric`, `Hash`.

### Using in Controls
```ruby
min_length = input('password_min_length')
describe policy do
  its('min_length') { should cmp >= min_length }
end
```

### Overriding at Runtime
```sh
cinc-auditor exec . --input-file=inputs.yml
cinc-auditor exec . --input password_min_length=16
```

### Rules
- **Never modify `inspec.yml` defaults** for environment-specific values — use override files
- **Any numerical check should use an input** (rule of thumb)
- Inputs are constants — values don't change during execution
- Profile author defines defaults; profile user overrides with input files

---

## 8. Overlay / Wrapper Profiles

Overlay profiles extend a base profile without copying controls:

```yaml
# overlay inspec.yml
depends:
  - name: base_profile
    path: ../base_profile
```

```ruby
# Include all, skip some
include_controls 'base_profile' do
  skip_control 'control-to-skip'
end

# Include only specific controls
require_controls 'base_profile' do
  control 'specific-control'
end

# Override properties of inherited controls
include_controls 'base_profile' do
  control 'some-control' do
    impact 0.5  # override impact only
  end
end
```

Never copy-paste controls from a base profile. Overlays stay in sync with upstream.

---

## 9. Generating Profiles from Security Guidance

### SAF CLI Stub Generation
```sh
saf generate inspec_profile -X benchmark.xccdf.xml -o profile_name
```
Generates complete `inspec.yml` and one `.rb` per control with all metadata. **No `describe` blocks** — those must be written by the developer.

### Control ID Type Flag (`-T`)
- `rule` — `SV-XXXXX` (default)
- `group` — `V-XXXXX`
- `cis` — `C-1.1.1.1`
- `version` — `RHEL-07-010020`

### Stub-to-Complete Workflow
1. Generate stubs from XCCDF
2. For each control: read check text → identify InSpec resource → read resource docs → write describe block → test → troubleshoot
3. Test against both vanilla and hardened targets
4. Lint and validate

---

## 10. Delta Process (Updating Profiles for New Guidance Versions)

When security guidance is updated:

```sh
# Quick update (minor revision, clear ID mappings)
saf generate update_controls4delta -X new_xccdf.xml -J profile.json -c controls/

# Full delta (new controls, major changes)
saf generate delta -X new_xccdf.xml -J profile.json -o new_controls/ -r report.md

# With fuzzy matching (IDs completely changed)
saf generate delta -X new_xccdf.xml -J profile.json -o new_controls/ -r report.md -M -c old_controls/
```

Delta preserves existing `describe` blocks while updating metadata. New controls get stubs only.

---

## 11. Testing and "Definition of Done"

A control is complete when:

1. All aspects of check text are addressed in `describe` blocks
2. N/A conditions are handled with `only_if` (impact: 0.0)
3. Manual conditions use `skip`
4. N/A and skip conditions are assessed **early** (fail-fast, before describe blocks)
5. Tested on **both vanilla and hardened** targets:
   - Fails on vanilla (non-compliant)
   - Passes on hardened (compliant)
   - N/A conditions reported correctly
   - No profile errors (no exceptions from missing files/services)

### Test Kitchen (for profiles with targets)
```yaml
# kitchen.yml
suites:
  - name: vanilla
    provisioner:
      playbook: spec/ansible/roles/ansible-role-vanilla.yml
  - name: hardened
    provisioner:
      playbook: spec/ansible/roles/ansible-role-hardened.yml
```

### Running Individual Controls
```sh
INSPEC_CONTROL='SV-230222' bundle exec kitchen verify vanilla
```

---

## 12. CI/CD Pipeline Pattern

Standard pipeline stages:
1. **PREP** — Install InSpec, SAF CLI, checkout code
2. **LINT** — `inspec check .` + `rubocop`
3. **DEPLOY** — Launch test targets
4. **HARDEN** — Apply configuration (Ansible)
5. **VALIDATE** — `inspec exec` with `--reporter cli json:results.json`
6. **VERIFY** — `saf validate threshold -i results.json -F threshold.yml`

Key patterns:
- `continue-on-error: true` on InSpec exec step (exit code 100 on any failure)
- `CHEF_LICENSE: accept` environment variable (prevents interactive prompt)
- Upload results to Heimdall for visualization
- Use threshold files to define acceptable compliance ratios

### Threshold File
```yaml
compliance:
  min: 80
failed:
  total:
    max: 2
error:
  total:
    max: 0
```

---

## 13. Resource Usage

### Prefer Built-in Resources
Use specific resources over raw `command` whenever possible:
- `file` — ownership, permissions, content
- `directory` — directory attributes
- `mount` / `etc_fstab` — mount points
- `package` — package installation
- `users` — user accounts
- `login_defs` — `/etc/login.defs`
- `parse_config_file` — arbitrary config files
- `command` — fallback for when no specific resource exists

### InSpec Shell (Interactive Testing)
```sh
inspec shell                          # local
inspec shell -t docker://container    # against target
```
Use to explore resources, test describe blocks interactively, and debug controls.

---

## 14. Reporting

```sh
# Multiple reporters
inspec exec . --reporter cli json:results.json

# Enhanced outcomes (Passed, Failed, N/A, Not Reviewed, Error)
inspec exec . --enhanced-outcomes

# Timestamped output
inspec exec . --reporter json:oci-$(date +"%Y-%m-%d-%H-%M-%S").json

# View summary
saf view summary -i results.json

# Apply manual attestations
saf attest apply -i results.json attestation.json -o attested_results.json
```

Results load into [Heimdall-Lite](https://heimdall-lite.mitre.org/) for visualization, comparison, and DISA Checklist (CKL) export.

---

## 15. RuboCop Configuration for InSpec Profiles

Key settings (from MITRE SAF standard `.rubocop.yml`):
- `Layout/LineLength: Max: 1500` — STIG/CIS metadata strings are long
- `Metrics/BlockLength: Max: 1000` — controls can be very long
- `Style/NumericPredicate: Enabled: false` — **required**, enabling introduces profile errors
- `Style/BlockDelimiters: Enabled: false` — InSpec uses both `do..end` and `{..}`
- `libraries/**/*` excluded from all cops
- `Naming/FileName: Enabled: false` — control files use non-standard names

---

## 16. STIG Development Concepts

### Hierarchy
```
NIST 800-53 → CCIs → SRGs (platform-independent) → STIGs (platform-specific)
```

### Requirement Statuses
- **Applicable – Configurable**: Can be checked and configured
- **Applicable – Inherently Meets**: Component always meets this (can't be changed)
- **Applicable – Does Not Meet**: Component cannot meet this requirement
- **Not Applicable**: Requirement doesn't apply to this component

### Check Text Style (from DISA Vendor STIG Process Guide)
- State N/A conditions first
- Don't restate the requirement
- Use action verbs: "verify", "navigate", "identify", "type"
- Don't use "should", "shall", "please"
- Must include finding statement: "If [condition], this is a finding."

### Fix Text Style
- Specific steps to configure compliance
- Use action verbs: "ensure", "configure", "set", "select"
- Don't restate the requirement
- Don't include finding statements

---

## 17. SAF Ecosystem Tools

| Tool | Purpose |
|------|---------|
| **InSpec / CINC Auditor** | Compliance validation testing |
| **SAF CLI** | Profile generation, delta updates, attestations, threshold validation, format conversion |
| **Heimdall** (Lite/Server) | Results visualization, dashboards, CKL export |
| **Vulcan** | STIG authorship platform with peer review workflow |
| **Ansible roles** | Hardening automation (pattern: `ansible-{platform}-stigready-hardening`) |

### SAF CLI Key Commands
```sh
saf generate inspec_profile -X xccdf.xml              # Generate profile stubs
saf generate delta -X new.xml -J profile.json -o out/  # Update profile for new guidance
saf view summary -i results.json                       # Quick compliance overview
saf validate threshold -i results.json -F threshold.yml # Pipeline pass/fail
saf attest apply -i results.json attestation.json -o out.json  # Manual attestations
saf convert <format> -i input -o output                # Format conversion
```

---

## 18. Key Principles

1. **Compliance as Code** — Security guidance and automated tests are two representations of the same requirements
2. **Separation of Concerns** — Test logic (controls) / test data (inputs) / results (reports)
3. **Never modify `inspec.yml` for runtime values** — use override files
4. **Use built-in resources** over raw `command` calls
5. **Parameterize everything** — hardcoded values become inputs
6. **Tag everything** — full CIS/STIG metadata for downstream tool fidelity
7. **Read-only testing** — InSpec validates; other tools remediate
8. **Overlay over copy** — use profile dependencies, not duplicated controls
9. **Generate from XCCDF** — SAF CLI creates stubs from benchmark documents
10. **Test-driven development** — validate before hardening to establish baseline
11. **Fail fast** — check preconditions before expensive test logic
12. **Find the outsiders** — for large datasets, search for violations rather than checking every item
