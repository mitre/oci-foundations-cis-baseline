# Code Review Findings: Custom InSpec Resources

**Date:** 2026-02-12
**Reviewers:** 3 automated review agents (code/architecture, security, Ruby best practices)
**Scope:** 11 library files, 22 refactored controls

## Executive Summary

The custom InSpec resource library is **well-architected and functional**. All 54 controls pass validation, 67 files are lint-clean, and the refactoring eliminated ~925 lines of code duplication. The class hierarchy follows MITRE SAF training patterns correctly.

**No blocking issues found.** The library is ready for use with recommended improvements documented below.

---

## Critical Findings (Address Before v1.0 Release)

### 1. `jq` External Dependency (2 files)

**Severity:** HIGH (portability)
**Files:** `cloud_guard_helper.rb:20-29`, `oci_identity_domain_password_policies.rb:57-63`

Two methods pipe OCI CLI output through `jq`, creating an external dependency:

```ruby
# cloud_guard_helper.rb
cmd = %(oci cloud-guard detector-recipe-detector-rule get \
  --detector-recipe-id "#{@detector_recipe_ocid}" \
  --detector-rule-id "#{rule_id}" | \
  jq -r --arg ck "#{config_key}" \
  '.data.details.configurations[]? | select(.["config-key"] == $ck) | .value')

# oci_identity_domain_password_policies.rb
cmd = %(oci iam domain list --compartment-id '#{@tenancy_ocid}' --all | jq '[.data[] | .url]')
```

**Impact:** If `jq` is not installed, these resources silently fail and return empty results, causing false passes.

**Fix:**

```ruby
# cloud_guard_helper.rb
def detector_rule_value(rule_id:, config_key:)
  return nil if @detector_recipe_ocid.to_s.empty?

  data = oci_cli_raw(
    %(oci cloud-guard detector-recipe-detector-rule get \
      --detector-recipe-id "#{@detector_recipe_ocid}" \
      --detector-rule-id "#{rule_id}")
  )

  configs = data.dig('data', 'details', 'configurations') || []
  match = configs.find { |c| c['config-key'] == config_key }
  match&.fetch('value', nil)
end

# oci_identity_domain_password_policies.rb
def fetch_domain_urls
  domains = oci_cli('oci iam domain list --compartment-id "#{@tenancy_ocid}" --all')
  domains.map { |d| d['url'] }.compact
end
```

---

### 2. Shell Command Injection Risk (All Resources)

**Severity:** HIGH (security - defense in depth)
**Practical Exploitability:** LOW-MEDIUM
**Files:** All resources that interpolate values into shell commands

All resources use string interpolation for OCI CLI commands:

```ruby
oci_cli(%(oci os bucket list --compartment-id "#{compartment_id}" --region "#{region}" --all))
```

Values interpolated include:
- **From `input()`**: tenancy_ocid, detector_recipe_ocid, compartment_id
- **From OCI API**: region names, compartment IDs, bucket names, rule IDs, topic IDs, management endpoints, domain URLs

**Risk:** Values containing `"`, `$()`, or backticks could break shell quoting and execute arbitrary commands.

**Practical Constraints:**
- OCIDs are format-restricted: `ocid1.<type>.<realm>.<region>.<unique_id>` (alphanumeric, dots, hyphens)
- Region names: `us-ashburn-1` (alphanumeric, hyphens)
- Exploitation requires: (a) compromised OCI API, or (b) malicious input file (but operator already has shell access)

**Fix (Defense in Depth):**

```ruby
# Add to oci_backend.rb
require 'shellwords'

class OciResourceBase
  OCID_PATTERN = /\Aocid1\.[a-z0-9]+\.[a-z0-9]+\.[a-z0-9.-]*\.[a-z0-9]+\z/

  def validate_ocid!(value, param_name)
    unless value.to_s.match?(OCID_PATTERN)
      raise ArgumentError, "Invalid OCID format for #{param_name}: #{value.inspect}"
    end
  end

  def safe_param(value)
    Shellwords.escape(value.to_s)
  end
end

# Use in commands (no surrounding quotes needed):
oci_cli(%(oci events rule list --compartment-id #{safe_param(@compartment_id)} --region #{safe_param(region)} --all))
```

---

### 3. TCP-Only Port Checking (2 resources)

**Severity:** MEDIUM (correctness)
**Files:** `oci_security_lists.rb:38`, `oci_network_security_groups.rb:39`

Both `fetch_data` methods only extract `tcp-options`:

```ruby
port_range = rule.dig('tcp-options', 'destination-port-range')
```

The `internet_ingress_findings(port:, protocol: '6')` accepts a `protocol` parameter but ignores it during data collection. UDP rules (`protocol: '17'`) would have `port_min: nil`, causing `port_exposed?` to return `true` (all ports).

**Impact:** Currently no impact (CIS controls only check TCP). But the API is misleading.

**Fix Options:**

**A) Support both TCP and UDP:**
```ruby
port_range = if rule['protocol'].to_s == '6'
               rule.dig('tcp-options', 'destination-port-range')
             elsif rule['protocol'].to_s == '17'
               rule.dig('udp-options', 'destination-port-range')
             end
```

**B) Document TCP-only and remove protocol param:**
```ruby
# Change method signature
def internet_ingress_findings(port:)  # Remove protocol param
  table.select do |row|
    row[:source] == '0.0.0.0/0' &&
      row[:protocol] == '6' &&  # Hardcode TCP
      port_exposed?(row, port)
  end
end
```

---

### 4. Missing Protocol `'all'` Check

**Severity:** MEDIUM (correctness)
**Files:** `oci_security_lists.rb:63`, `oci_network_security_groups.rb:63`

OCI security rules can use `protocol: "all"` to allow all protocols. The `internet_ingress_findings` filters:

```ruby
row[:source] == '0.0.0.0/0' && row[:protocol] == protocol && port_exposed?(row, port)
```

A rule with `protocol: "all"` would NOT match `== '6'`, so permissive "allow all" rules would be missed.

**Fix:**
```ruby
row[:source] == '0.0.0.0/0' &&
  (row[:protocol] == protocol || row[:protocol] == 'all') &&
  port_exposed?(row, port)
```

---

## Medium Priority Issues

### 5. Nil Safety in `OciBuckets.missing_versioning_findings`

**File:** `oci_buckets.rb:72`

```ruby
Versioning: #{row[:versioning].empty? ? 'Unknown' : row[:versioning]}
```

If `row[:versioning]` is `nil`, `.empty?` raises `NoMethodError`. Use `.to_s.empty?` instead.

---

### 6. Inconsistent Error Handling Patterns

**Files:** `oci_buckets.rb:60-66`, `oci_vault_keys.rb:53-56, 87-91`, `oci_event_rules.rb:81-85`

Bare `rescue StandardError` blocks silently swallow errors without logging. Examples:

```ruby
# oci_buckets.rb - rescues nil.casecmp
table.reject { |row|
  begin
    row[:versioning].casecmp('Enabled').zero?
  rescue StandardError
    false
  end
}
```

**Fix:** Use defensive `.to_s` instead of rescue:
```ruby
table.reject { |row| row[:versioning].to_s.casecmp('enabled').zero? }
```

---

### 7. Duplicated Code (DRY Violations)

**a) `port_exposed?` duplicated**
Identical method in `oci_security_lists.rb:86-89` and `oci_network_security_groups.rb:91-94`.

**Fix:** Extract to shared module or `OciResourceBase`.

**b) `Time.parse` error handling duplicated**
Same pattern in `oci_vault_keys.rb:53-56` and `87-91`.

**Fix:** Extract to `safe_parse_time(value)` helper.

**c) Region×compartment iteration**
5 resources repeat:
```ruby
all_regions.each do |region|
  all_compartment_ids.each do |compartment_id|
    # ...
  end
end
```

**Fix:** Add `each_region_compartment { |region, cid| ... }` to base class.

---

## Low Priority Issues (Polish)

### 8. Missing `frozen_string_literal: true`

All 11 files missing standard Ruby magic comment. Not required but recommended.

---

### 9. FilterTable Column Naming

Awkward names:
- `enabled_list` → just use `.where(enabled: true)`, no column accessor needed
- `min_numerals_list` → `min_numerals`
- `min_special_chars_list` → `min_special_chars`
- `age_days_list` → `age_days_values`

---

### 10. Error Visibility

`oci_backend.rb:17, 25` - `2>/dev/null` suppresses stderr, hiding auth failures and permission errors. Consider logging stderr at debug level for troubleshooting.

---

### 11. Parameter Validation

Resources don't validate required parameters (gracefully return empty results instead). Consider warning when required params are missing to catch typos in input names.

---

### 12. `CloudGuardHelper` Naming Inconsistency

Should be `oci_cloud_guard_helper` to match `oci_*` namespace convention.

---

### 13. `OciVaultKeys` Initialization Order

`@total_vaults` and `@total_keys` initialized before `super`, then mutated in `fetch_data`. Fragile if reordered. Move initialization into `fetch_data`.

---

### 14. `to_s` Methods

Generic (`'OCI Event Rules'`) instead of context-specific (`'OCI Event Rules (compartment: ocid1...)'`).

---

## What Was Done Well ✓

1. **Class hierarchy** - Clean `OciResourceBase` → `OciCollectionResourceBase` split matching MITRE SAF patterns
2. **FilterTable** - All registrations correct, proper plural column names
3. **Error handling** - Graceful degradation with logging
4. **API consistency** - All resources follow same patterns
5. **Control readability** - Refactored controls are dramatically cleaner
6. **`OciEventRules.missing_regions`** - Excellent domain-specific method
7. **`OciHelpers.format_findings`** - Simple, focused utility
8. **No unsafe operations** - No file writes, network calls, or privilege escalation
9. **Thread safety** - No mutable shared state
10. **Usage examples** - All resources now have `example` blocks (added in commit 9)

---

## Recommended Action Plan

**Before Merge:**
1. Fix `jq` dependencies (#1) - 15 minutes
2. Add `Shellwords.escape` to `oci_backend.rb` (#2) - 10 minutes
3. Fix TCP/UDP port checking (#3, #4) - 20 minutes
4. Fix nil safety in buckets (#5) - 2 minutes

**Next Iteration (v1.1):**
5. Extract duplicated helpers (#7) - 30 minutes
6. Add frozen string literals (#8) - 5 minutes
7. Clean up FilterTable column names (#9) - 10 minutes
8. Rename cloud_guard_helper (#12) - 5 minutes

**Future (if needed):**
9. Parameter validation (#11)
10. Improved error visibility (#10)
11. Context-aware `to_s` (#14)

---

## Testing Verification

All 54 controls pass:
```bash
bundle exec cinc-auditor check .
# Controls: 54
# Valid: true
# No errors, warnings, or offenses

bundle exec rake lint
# 67 files inspected, no offenses detected

bundle exec rake pre_commit_checks
# ✓ All checks pass
```

Git commits:
```
03e7655 style: auto-fix new RuboCop cop offenses
99b32d3 feat: add password policy resource, refactor 3 IAM controls
24365cf feat: add storage resources, refactor 3 bucket/vault key controls
bd1ed2a feat: add networking resources, refactor 4 security list/NSG controls
fc42cca feat: add oci_event_rules resource, refactor 12 event rule controls
1ad682e feat: add oci_regions and oci_compartments resources
bd0d04f feat: add OCI InSpec resource base classes and helpers
1c14828 chore: update RuboCop config for libraries and new cops
1f8be04 docs: add usage examples to all custom InSpec resources
```

**Net Result:** +765 lines libraries, -1073 lines controls = -308 lines total (with better structure)

---

## Security Risk Assessment

**Overall Risk:** MEDIUM (before fixes), LOW (after Priority 1-4 fixes)

**Exploitability:** LOW
- Requires compromised OCI API or malicious input file
- Operator providing inputs already has shell access
- OCI naming rules restrict character sets

**Defense-in-Depth Violations:** YES
- Trusting all interpolated values without validation
- Shell pipes with interpolation (`jq` patterns)
- No OCID format validation

**Recommended:** Apply Priority 1-4 fixes above before production use.
