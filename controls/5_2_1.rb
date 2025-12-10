control '5_2_1' do
  title 'Ensure Block Volumes are encrypted with Customer Managed Keys (CMK).'

  desc <<~DESC
    Oracle Cloud Infrastructure Block Volume service lets you dynamically provision and manage
    block storage volumes. By default, the Oracle service manages the keys that encrypt block
    volumes. Block Volumes can also be encrypted using a customer managed key. Terminated
    Block Volumes cannot be recovered and any data on a terminated volume is permanently lost.
    However, Block Volumes can exist in a terminated state within the OCI Portal and CLI for
    some time after deleting. As such, any Block Volumes in this state should not be
    considered when assessing this policy. Encryption of block volumes provides an additional
    level of security for your data. Management of encryption keys is critical to protecting
    and accessing protected data. Customers should identify block volumes encrypted with
    Oracle service managed keys in order to determine if they want to manage the keys for
    certain volumes and then apply their own key lifecycle management to the selected block
    volumes.
  DESC

  desc 'check', <<~CHECK
    From Console: Login to the OCI Console. Click the search bar at the top of the screen.

    Type 'Advanced Resource Query' and press return. Click Advanced resource query. Enter the
    following query in the query box: query volume resources For each block volume returned,
    click the link under Display name. Ensure the value for Encryption Key is not
    Oracle-managed key. Repeat for other subscribed regions.

    From CLI: Execute the following command:
    for region in $(oci iam region-subscription list --all | jq -r '.data[] | ."region-name"'); do
      for volid in $(oci search resource structured-search --region $region --query-text "query volume resources" --limit 1000 2>/dev/null | jq -r '.data.items[]?.identifier'); do
        oci bv volume get --volume-id $volid --region $region 2>/dev/null |
          jq -r '.data | select(."kms-key-id" == null and ."lifecycle-state" != "TERMINATED") | .id'
      done
    done
    Ensure the query returns no results.
  CHECK

  desc 'fix', <<~FIX
    From Console: Follow the audit procedure above. For each block volume returned, click the

    link under Display name. If the value for Encryption Key is Oracle-managed key , click
    Assign next to Oracle-managed key . Select a Vault Compartment and Vault . Select a Master
    Encryption Key Compartment and Master Encryption key . Click Assign . From CLI: Follow the
    audit procedure. For each block volume identified, get the OCID. Execute the following
    command: oci bv volume-kms-key update --volume-id <volume OCID> --kms-key-id <kms key OCID>
  FIX

  desc 'potential_impacts', <<~POTENTIAL_IMPACTS
    [object Object]
  POTENTIAL_IMPACTS

  impact 0.5

  tag check_id: 'C-5_2_1'
  tag severity: 'medium'
  tag gid: 'CIS-5_2_1'
  tag rid: 'xccdf_cis_cis_rule_5_2_1'
  tag stig_id: '5.2.1'
  tag gtitle: '<GroupDescription></GroupDescription>'

  tag cci: [
    'CCI-001199',
    'CCI-002472',
    'CCI-000183',
    'CCI-000051',
    'CCI-002856',
    'CCI-003205'
  ]

  tag nist: [
    'SC-28',
    'SC-28',
    'IA-5 g',
    'AC-8 a',
    'CP-12',
    'SA-12 (8)'
  ]

  # regions_response = json(command: 'oci iam region-subscription list --all')
  # regions_data = regions_response.params.fetch('data', [])
  # regions = regions_data.map { |region| region['region-name'] }.compact

  # volumes_missing_cmk = []

  # regions.each do |region|
  #   search_cmd = %(oci search resource structured-search --region "#{region}" --query-text "query volume resources" --limit 1000 2>/dev/null)
  #   search_response = json(command: search_cmd)
  #   volume_ids = search_response.params.fetch('data', {}).fetch('items', []).map { |item| item['identifier'] }.compact

  #   volume_ids.each do |volume_id|
  #     volume_details = json(command: %(oci bv volume get --volume-id "#{volume_id}" --region "#{region}" 2>/dev/null))
  #     volume_data = volume_details.params.fetch('data', {})

  #     next if volume_data.empty?
  #     puts volume_data
  #     lifecycle_state = volume_data['lifecycle-state']
  #     kms_key_id = volume_data['kms-key-id']

  #     next if lifecycle_state.to_s.casecmp('TERMINATED').zero?
  #     next unless kms_key_id.to_s.empty?

  #     volumes_missing_cmk << {
  #       'display-name' => volume_data['display-name'],
  #       'region' => region
  #     }.compact
  #   end
  # end

  # describe 'Ensure Block Volumes are encrypted with Customer Managed Keys (CMK).' do
  #   subject { volumes_missing_cmk }
  #   it { should be_empty }
  # end
end
