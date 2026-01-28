control '4_16' do
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
    "data[*].[\"time-created\",\"display-name\",\"lifecycle-state\"]" Ensure the date of the
    Master Encryption key is no more than 365 days old and is also in the ENABLED state.
  CHECK

  desc 'fix', <<~FIX
    From Console: Login into OCI Console. Select Identity & Security from the Services menu.

    Select Vault . Click on the individual Vault under the Name heading. Click on the menu
    next to the time created. Click Rotate Key From CLI: Execute the following: oci kms
    management key rotate --key-id <key-ocid> --endpoint <management-endpoint-url>
  FIX

  impact 0.5

  tag check_id: 'C-4_16'
  tag severity: 'medium'
  tag gid: 'CIS-4_16'
  tag rid: 'xccdf_cis_cis_rule_4_16'
  tag stig_id: '4.16'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag 'documentable'

  require 'time'

  regions_response = json(command: 'oci iam region-subscription list --all')
  regions_data = regions_response.params.fetch('data', [])
  regions = regions_data.map { |region| region['region-name'] }.compact

  compartments_response = json(command: 'oci iam compartment list --include-root --compartment-id-in-subtree TRUE --all 2>/dev/null')
  compartments_data = compartments_response.params.fetch('data', [])
  compartment_ids = compartments_data.map { |compartment| compartment['id'] }.compact

  now = Time.now.utc
  cutoff_time = now - (365 * 24 * 60 * 60)
  non_compliant_keys = []
  total_keys = 0
  total_vaults = 0

  regions.each do |region|
    compartment_ids.each do |compartment_id|
      vaults_response = json(
        command: %(oci kms management vault list --compartment-id "#{compartment_id}" --region "#{region}" --all 2>/dev/null)
      )
      vaults = vaults_response.params.fetch('data', [])

      vaults.each do |vault|
        next unless vault['lifecycle-state'] == 'ACTIVE'

        management_endpoint = vault['management-endpoint'].to_s.strip
        next if management_endpoint.empty?

        total_vaults += 1

        keys_response = json(
          command: %(oci kms management key list --compartment-id "#{compartment_id}" --endpoint "#{management_endpoint}" --all 2>/dev/null)
        )
        keys = keys_response.params.fetch('data', [])

        keys.each do |key|
          total_keys += 1

          created_at = key['time-created']
          lifecycle_state = key['lifecycle-state']
          created_time = nil

          begin
            created_time = Time.parse(created_at.to_s).utc unless created_at.to_s.empty?
          rescue StandardError
            created_time = nil
          end

          state_ok = lifecycle_state.to_s.strip.upcase == 'ENABLED'
          time_ok = created_time && created_time >= cutoff_time

          next if state_ok && time_ok

          age_days = created_time ? ((now - created_time) / 86_400).floor : nil

          non_compliant_keys << {
            'display_name' => key['display-name'],
            'key_id' => key['id'],
            'vault_name' => vault['display-name'],
            'vault_id' => vault['id'],
            'region' => region,
            'compartment_id' => compartment_id,
            'lifecycle_state' => lifecycle_state,
            'time_created' => created_at,
            'age_days' => age_days
          }.compact
        end
      end
    end
  end

  if total_vaults.zero?
    impact 0.0
    describe 'Ensure customer created Customer Managed Key (CMK) is rotated at least annually' do
      skip 'No vaults found in tenancy.'
    end
  elsif total_keys.zero?
    impact 0.0
    describe 'Ensure customer created Customer Managed Key (CMK) is rotated at least annually' do
      skip 'No master encryption keys found in tenancy.'
    end
  else
    describe 'Ensure customer created Customer Managed Key (CMK) is rotated at least annually' do
      subject { non_compliant_keys }
      it { should cmp [] }
    end
  end
end
