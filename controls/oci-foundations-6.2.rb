control 'oci-foundations-6.2' do
  title 'Ensure no resources are created in the root compartment'

  desc <<~DESC
    When you create a cloud resource such as an instance, block volume, or cloud network, you
    must specify to which compartment you want the resource to belong. Placing resources in
    the root compartment makes it difficult to organize and isolate those resources. Placing
    resources into a compartment will allow you to organize and have more granular access
    controls to your cloud resources.
  DESC

  desc 'check', <<~CHECK
    From Console: Login into the OCI Console. Click in the search bar, top of the screen. Type

    Advance Resource Query and hit enter . Click the Advanced Resource Query button in the
    upper right of the screen. Enter the following query into the query box: query VCN,
    instance, bootvolume, volume, filesystem, bucket, autonomousdatabase, database, dbsystem
    resources where compartmentId = '<tenancy-id>' Ensure query returns no results. From CLI:

    Execute the following command: oci search resource structured-search --query-text "query
    VCN, instance, volume, bootvolume, filesystem, bucket, autonomousdatabase, database,
    dbsystem resources where compartmentId = '<tenancy-id>'" Ensure query return no results.
  CHECK

  desc 'fix', <<~FIX
    From Console: Follow audit procedure above. For each item in the returned results, click

    the item name. Then select Move Resource or More Actions then Move Resource . Select a
    compartment that is not the root compartment in CHOOSE NEW COMPARTMENT . Click Move
    Resource . From CLI: Follow the audit procedure above. For each bucket item execute the
    below command: oci os bucket update --bucket-name <bucket-name> --compartment-id <not root
    compartment-id> For other resources use the change-compartment command for the resource
    type: oci <service-command> <resource-command> change-compartment --<item-id> <item-id>
    --compartment-id <not root compartment-id> i. Example for an Autonomous Database: oci db
    autonomous-database change-compartment --autonomous-database-id <autonmous-database-id>
    --compartment-id <not root compartment-id>
  FIX

  desc 'potential_impacts', <<~POTENTIAL_IMPACTS
    "Placing a resource in a compartment will
  POTENTIAL_IMPACTS

  impact 0.5

  tag severity: 'medium'
  tag benchmark_ref: '6.2'
  tag cis_level: 'Level 1'
  tag assessment_status: 'Automated'
  tag cis_controls: %w[3.12]

  tag cci: %w[CCI-001097]

  tag nist: ['SC-7']

  tenancy_ocid = input('tenancy_ocid')

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

  query_text = %(query VCN, instance, volume, bootvolume, filesystem, bucket, autonomousdatabase, database, dbsystem resources where compartmentId = '#{tenancy_ocid}')

  findings = []
  regions.each do |region|
    search_response = json(command: %(oci search resource structured-search --region "#{region}" --query-text "#{query_text}" --limit 1000 2>/dev/null))
    items = search_response.params.dig('data', 'items') || []

    items.each do |item|
      compartment_id = item['compartment-id'].to_s
      compartment_name = compartment_names_by_id[compartment_id] || 'Unknown'

      findings << <<~ENTRY.chomp
        Region: #{region}
        Resource Type: #{item['resource-type']}
        Name: #{item['display-name']}
        Identifier: #{item['identifier']}
        Compartment Name: #{compartment_name}
        Compartment ID: #{compartment_id}
        Lifecycle State: #{item['lifecycle-state']}
        Issue: Resource exists in the root compartment
      ENTRY
    end
  end

  numbered_findings = findings.each_with_index.map do |entry, index|
    "[#{index + 1}]\n#{entry}"
  end

  describe 'Resources in the root compartment' do
    it 'should not include VCN, instance, volume, boot volume, file system, bucket, autonomous database, database, or DB system resources' do
      expect(findings).to be_empty, <<~MSG
        Non-compliant findings:

        #{numbered_findings.join("\n\n")}
      MSG
    end
  end
end
