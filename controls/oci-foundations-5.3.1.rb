control 'oci-foundations-5.3.1' do
  title 'Ensure File Storage Systems are encrypted with Customer Managed Keys (CMK)'

  desc <<~DESC
    Oracle Cloud Infrastructure File Storage service (FSS) provides a durable, scalable,
    secure, enterprise-grade network file system. By default, the Oracle service manages the
    keys that encrypt FSS file systems. FSS file systems can also be encrypted using a
    customer managed key. Encryption of FSS systems provides an additional level of security
    for your data. Management of encryption keys is critical to protecting and accessing
    protected data. Customers should identify FSS file systems that are encrypted with Oracle
    service managed keys in order to determine if they want to manage the keys for certain FSS
    file systems and then apply their own key lifecycle management to the selected FSS file
    systems.
  DESC

  desc 'check', <<~CHECK
    From Console: Login into the OCI Console Click in the search bar, top of the screen. Type

    Advanced Resource Query and click enter. Click the Advanced Resource Query button in the
    upper right of the screen. Enter the following query in the query box: query filesystem
    resources For each file storage system returned click on the link under Display name
    Ensure Encryption Key does not say Oracle-managed key Repeat for other subscribed regions

    From CLI: Execute the following command: for region in `oci iam region list | jq -r

    '.data[] | .name'`; do for fssid in `oci search resource structured-search --region
    $region --query-text "query filesystem resources" 2>/dev/null | jq -r '.data.items[] |
    .identifier'` do output=`oci fs file-system get --file-system-id $fssid --region $region
    2>/dev/null | jq -r '.data | select(."kms-key-id" == "").id'` if [ ! -z "$output" ]; then
    echo $output; fi done done Ensure query returns no results
  CHECK

  desc 'fix', <<~FIX
    From Console: Follow the audit procedure above. For each File Storage System in the

    returned results, click the File System Storage Click Edit next to Encryption Key Select
    Encrypt using customer-managed keys Select the Vault Compartment and Vault Select the
    Master Encryption Key Compartment and Master Encryption key Click Save Changes From CLI:

    Follow the audit procedure. For each File Storage System identified get its OCID. Execute
    the following command: oci bv volume-kms-key update –volume-id <volume OCID> --kms-key-id
    <kms key OCID>
  FIX

  desc 'potential_impacts', <<~POTENTIAL_IMPACTS
    [object Object]
  POTENTIAL_IMPACTS

  impact 0.5

  tag severity: 'medium'
  tag benchmark_ref: '5.3.1'
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
  total_file_systems = 0

  regions.each do |region|
    search_response = json(command: %(oci search resource structured-search --region "#{region}" --query-text "query filesystem resources" --limit 1000 2>/dev/null))
    items = search_response.params.dig('data', 'items') || []
    file_system_ids = items.map { |item| item['identifier'] }.compact

    file_system_ids.each do |file_system_id|
      file_system_response = json(command: %(oci fs file-system get --file-system-id "#{file_system_id}" --region "#{region}" 2>/dev/null))
      file_system = file_system_response.params.fetch('data', {})
      next if file_system.empty?

      lifecycle_state = file_system['lifecycle-state']
      next if lifecycle_state == 'DELETED'

      total_file_systems += 1
      kms_key_id = file_system['kms-key-id'].to_s.strip
      next unless kms_key_id.empty?

      compartment_id = file_system['compartment-id'].to_s
      compartment_name = compartment_names_by_id[compartment_id] || 'Unknown'

      findings << <<~ENTRY.chomp
        Name: #{file_system['display-name']}
        ID: #{file_system['id']}
        Region: #{region}
        Compartment Name: #{compartment_name}
        Compartment ID: #{compartment_id}
        Lifecycle State: #{lifecycle_state}
        Issue: kms-key-id is unset (Oracle-managed key)
      ENTRY
    end
  end

  if total_file_systems.zero?
    impact 0.0
    describe 'Ensure File Storage Systems are encrypted with Customer Managed Keys (CMK)' do
      skip 'No File Storage Systems found in tenancy.'
    end
  else
    numbered_findings = findings.each_with_index.map do |entry, index|
      "[#{index + 1}]\n#{entry}"
    end

    describe 'File Storage file systems' do
      it 'should be encrypted with customer-managed keys (CMK)' do
        expect(findings).to be_empty, <<~MSG
          Non-compliant findings:

          #{numbered_findings.join("\n\n")}
        MSG
      end
    end
  end
end
