control 'oci-foundations-5.2.2' do
  title 'Ensure boot volumes are encrypted with Customer Managed Key (CMK).'

  desc <<~DESC
    When you launch a virtual machine (VM) or bare metal instance based on a platform image or
    custom image, a new boot volume for the instance is created in the same compartment. That
    boot volume is associated with that instance until you terminate the instance. By default,
    the Oracle service manages the keys that encrypt this boot volume. Boot Volumes can also
    be encrypted using a customer managed key. Encryption of boot volumes provides an
    additional level of security for your data. Management of encryption keys is critical to
    protecting and accessing protected data. Customers should identify boot volumes encrypted
    with Oracle service managed keys in order to determine if they want to manage the keys for
    certain boot volumes and then apply their own key lifecycle management to the selected
    boot volumes.
  DESC

  desc 'check', <<~CHECK
    From Console: Login into the OCI Console Click in the search bar, top of the screen. Type

    Advanced Resource Query and click enter. Click the Advanced Resource Query button in the
    upper right of the screen. Enter the following query in the query box: query bootvolume
    resources For each boot volume returned click on the link under Display name Ensure
    Encryption Key does not say Oracle managed key Repeat for other subscribed regions From
    CLI: Execute the following command: for region in `oci iam region list | jq -r '.data[] |
    .name'`; do for bvid in `oci search resource structured-search --region $region
    --query-text "query bootvolume resources" 2>/dev/null | jq -r '.data.items[] |
    .identifier'` do output=`oci bv boot-volume get --boot-volume-id $bvid 2>/dev/null | jq -r
    '.data | select(."kms-key-id" == null).id'` if [ ! -z "$output" ]; then echo $output; fi
    done done Ensure query returns no results.
  CHECK

  desc 'fix', <<~FIX
    From Console: Follow the audit procedure above. For each Boot Volume in the returned

    results, click the Boot Volume name Click Assign next to Encryption Key Select the Vault
    Compartment and Vault Select the Master Encryption Key Compartment and Master Encryption
    key Click Assign From CLI: Follow the audit procedure. For each boot volume identified get
    its OCID. Execute the following command: oci bv boot-volume-kms-key update
    --boot-volume-id <Boot Volume OCID> --kms-key-id <KMS Key OCID>
  FIX

  desc 'potential_impacts', <<~POTENTIAL_IMPACTS
    [object Object]
  POTENTIAL_IMPACTS

  impact 0.5

  tag severity: 'medium'
  tag benchmark_ref: '5.2.2'
  tag cis_level: 'Level 2'
  tag assessment_status: 'Automated'
  tag cis_controls: %w[3.11]

  tag cci: %w[CCI-001199]

  tag nist: ['SC-28']

  regions_response = json(command: 'oci iam region-subscription list --all')
  regions_data = regions_response.params.fetch('data', [])
  regions = regions_data.map { |region| region['region-name'] }.compact

  compartments_response = json(command: 'oci iam compartment list --include-root --compartment-id-in-subtree TRUE --all 2>/dev/null')
  compartments_data = compartments_response.params.fetch('data', [])
  compartment_names_by_id = compartments_data.each_with_object({}) do |compartment, map|
    compartment_id = compartment['id'].to_s
    next if compartment_id.empty?

    map[compartment_id] = compartment['name']
  end

  findings = []
  total_boot_volumes = 0

  regions.each do |region|
    search_response = json(command: %(oci search resource structured-search --region "#{region}" --query-text "query bootvolume resources" --limit 1000 2>/dev/null))
    items = search_response.params.dig('data', 'items') || []
    boot_volume_ids = items.map { |item| item['identifier'] }.compact

    boot_volume_ids.each do |boot_volume_id|
      boot_volume_response = json(command: %(oci bv boot-volume get --boot-volume-id "#{boot_volume_id}" --region "#{region}" 2>/dev/null))
      boot_volume = boot_volume_response.params.fetch('data', {})
      next if boot_volume.empty?

      lifecycle_state = boot_volume['lifecycle-state']
      next if lifecycle_state == 'TERMINATED'

      total_boot_volumes += 1
      kms_key_id = boot_volume['kms-key-id'].to_s.strip
      next unless kms_key_id.empty?

      compartment_id = boot_volume['compartment-id'].to_s
      compartment_name = compartment_names_by_id[compartment_id] || 'Unknown'

      findings << <<~ENTRY.chomp
        Name: #{boot_volume['display-name']}
        ID: #{boot_volume['id']}
        Region: #{region}
        Compartment Name: #{compartment_name}
        Compartment ID: #{compartment_id}
        Lifecycle State: #{lifecycle_state}
        Issue: kms-key-id is unset (Oracle-managed key)
      ENTRY
    end
  end

  if total_boot_volumes.zero?
    impact 0.0
    describe 'Ensure boot volumes are encrypted with Customer Managed Key (CMK)' do
      skip 'No boot volumes found in tenancy.'
    end
  else
    numbered_findings = findings.each_with_index.map do |entry, index|
      "[#{index + 1}]\n#{entry}"
    end

    describe 'Boot volumes' do
      it 'should be encrypted with customer-managed keys (CMK)' do
        expect(findings).to be_empty, <<~MSG
          Non-compliant findings:

          #{numbered_findings.join("\n\n")}
        MSG
      end
    end
  end
end
