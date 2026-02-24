control 'oci-foundations-4.16' do
  title 'Ensure customer created Customer Managed Key (CMK) is rotated at least annually'

  desc <<~DESC
    Oracle Cloud Infrastructure Vault securely stores master encryption keys that protect your
    encrypted data. You can use the Vault service to rotate keys to generate new cryptographic
    material. Periodically rotating keys limits the amount of data encrypted by one key
    version. Rotating keys annually limits the data encrypted under one key version. Key
    rotation thereby reduces the risk in case a key is ever compromised.
  DESC

  desc 'check', <<~CHECK
    From Console: Login into OCI Console. Select Identity & Security from the Services menu.

    Select Vault . Click on the individual Vault under the Name heading. Ensure the date of
    each Master Encryption key under the Created column of the Master Encryption key is no
    more than 365 days old, and that the key is in the ENABLED state Repeat for all Vaults in
    all compartments From CLI: Execute the following for each Vault in each compartment oci
    kms management key list --compartment-id '<compartment-id>' --endpoint
    '<management-endpoint-url>' --all --query
    "data[*].["time-created","display-name","lifecycle-state"]" Ensure the date of the
    Master Encryption key is no more than 365 days old and is also in the ENABLED state.
  CHECK

  desc 'fix', <<~FIX
    From Console: Login into OCI Console. Select Identity & Security from the Services menu.

    Select Vault . Click on the individual Vault under the Name heading. Click on the menu
    next to the time created. Click Rotate Key From CLI: Execute the following: oci kms
    management key rotate --key-id <key-ocid> --endpoint <management-endpoint-url>
  FIX

  impact 0.5

  tag severity: 'medium'
  tag benchmark_ref: '4.16'
  tag cis_level: 'Level 1'
  tag assessment_status: 'Automated'
  tag cis_controls: %w[0.0]

  tag cci: %w[CCI-002438]

  tag nist: ['SC-12']

  vault_keys = oci_vault_keys

  if vault_keys.total_vaults.zero?
    impact 0.0
    describe 'Ensure customer created Customer Managed Key (CMK) is rotated at least annually' do
      skip 'No vaults found in tenancy.'
    end
  elsif vault_keys.total_keys.zero?
    impact 0.0
    describe 'Ensure customer created Customer Managed Key (CMK) is rotated at least annually' do
      skip 'No master encryption keys found in tenancy.'
    end
  else
    findings = vault_keys.non_compliant_findings(max_age_days: 365)
    numbered_findings = oci_helpers.format_findings(findings)

    describe 'Customer-managed encryption keys' do
      it 'should be enabled and rotated within the last 365 days' do
        expect(findings).to be_empty, <<~MSG
          Non-compliant findings:

          #{numbered_findings.join("\n\n")}
        MSG
      end
    end
  end
end
