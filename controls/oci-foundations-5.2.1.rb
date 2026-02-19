control 'oci-foundations-5.2.1' do
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

  tag severity: 'medium'
  tag benchmark_ref: '5.2.1'
  tag cis_level: 'Level 2'
  tag assessment_status: 'Automated'
  tag cis_controls: %w[3.11]

  tag cci: %w[CCI-001199]

  tag nist: ['SC-28']

  regions_response = json(command: 'oci iam region-subscription list --all')
  regions_data = regions_response.params.fetch('data', [])
  regions = regions_data.map { |region| region['region-name'] }.compact

  findings = []
  total_block_volumes = 0

  regions.each do |region|
    search_response = json(command: %(oci search resource structured-search --region "#{region}" --query-text "query volume resources" --limit 1000 2>/dev/null))
    items = search_response.params.dig('data', 'items') || []
    volume_ids = items.map { |item| item['identifier'] }.compact

    volume_ids.each do |volume_id|
      volume_response = json(command: %(oci bv volume get --volume-id "#{volume_id}" --region "#{region}" 2>/dev/null))
      volume = volume_response.params.fetch('data', {})
      next if volume.empty?

      lifecycle_state = volume['lifecycle-state']
      next if lifecycle_state == 'TERMINATED'

      total_block_volumes += 1
      kms_key_id = volume['kms-key-id'].to_s.strip
      next unless kms_key_id.empty?

      findings << <<~ENTRY.chomp
        Name: #{volume['display-name']}
        ID: #{volume['id']}
        Region: #{region}
        Compartment ID: #{volume['compartment-id']}
        Lifecycle State: #{lifecycle_state}
        Issue: kms-key-id is unset (Oracle-managed key)
      ENTRY
    end
  end

  if total_block_volumes.zero?
    impact 0.0
    describe 'Ensure Block Volumes are encrypted with Customer Managed Keys (CMK).' do
      skip 'No block volumes found in tenancy.'
    end
  else
    numbered_findings = findings.each_with_index.map do |entry, index|
      "[#{index + 1}]\n#{entry}"
    end

    describe 'Block volumes' do
      it 'should be encrypted with customer-managed keys (CMK)' do
        expect(findings).to be_empty, <<~MSG
          Non-compliant findings:

          #{numbered_findings.join("\n\n")}
        MSG
      end
    end
  end
end
