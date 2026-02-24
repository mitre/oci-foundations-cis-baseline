control 'oci-foundations-5.1.1' do
  title 'Ensure no Object Storage buckets are publicly visible.'

  desc <<~DESC
    A bucket is a logical container for storing objects. It is associated with a single
    compartment that has policies that determine what action a user can perform on a bucket
    and on all the objects in the bucket. By Default a newly created bucket is private. It is
    recommended that no bucket be publicly accessible. Removing unfettered reading of objects
    in a bucket reduces an organization's exposure to data loss.
  DESC

  desc 'check', <<~CHECK
    From Console: Login into the OCI Console Click in the search bar at the top of the screen.

    Type Advanced Resource Query and click enter . Click the Advanced Resource Query button in
    the upper right of the screen. Enter the following query in the query box: query bucket
    resources where (publicAccessType == 'ObjectRead') || (publicAccessType ==
    'ObjectReadWithoutList') Ensure query returns no results From CLI: Execute the following
    command: oci search resource structured-search --query-text "query bucket resources where
    (publicAccessType == 'ObjectRead') || (publicAccessType == 'ObjectReadWithoutList')"
    Ensure query returns no results Cloud Guard To Enable Cloud Guard Auditing: Ensure Cloud
    Guard is enabled in the root compartment of the tenancy. For more information about
    enabling Cloud Guard, please look at the instructions included in Recommendation 3.15.

    From Console: Type Cloud Guard into the Search box at the top of the Console. Click Cloud

    Guard from the “Services” submenu. Click Detector Recipes in the Cloud Guard menu. Click
    OCI Configuration Detector Recipe (Oracle Managed) under the Recipe Name column. Find
    Bucket is public in the Detector Rules column. Verify that the Bucket is public Detector
    Rule is Enabled. From CLI: Verify the Bucket is public Detector Rule in Cloud Guard is
    enabled to generate Problems if Object Storage Buckets are configured to be accessible
    over the public Internet with the following command: oci cloud-guard
    detector-recipe-detector-rule get --detector-recipe-id <insert detector recipe ocid>
    --detector-rule-id BUCKET_IS_PUBLIC
  CHECK

  desc 'fix', <<~FIX
    From Console: Follow the audit procedure above. For each bucket in the returned results,

    click the Bucket Display Name Click Edit Visibility Select Private Click Save Changes From
    CLI: Follow the audit procedure For each of the buckets identified, execute the following
    command: oci os bucket update --bucket-name <bucket-name> --public-access-type
    NoPublicAccess
  FIX

  desc 'potential_impacts', <<~POTENTIAL_IMPACTS
    For updating an existing bucket, care should be taken to ensure objects in the bucket can
    be accessed through either IAM policies or pre-authenticated requests.
  POTENTIAL_IMPACTS

  impact 0.5

  tag severity: 'medium'
  tag benchmark_ref: '5.1.1'
  tag cis_level: 'Level 1'
  tag assessment_status: 'Automated'
  tag cis_controls: %w[3.3]

  tag cci: %w[CCI-000213]

  tag nist: ['AC-3']

  tenancy_ocid = input('tenancy_ocid')
  
  query_text = %(query bucket resources where (publicAccessType == 'ObjectRead') || (publicAccessType == 'ObjectReadWithoutList'))

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
  seen_identifiers = {}

  regions.each do |region|
    search_response = json(
      command: %(oci search resource structured-search --region "#{region}" --query-text "#{query_text}" --limit 1000 2>/dev/null)
    )
    items = search_response.params.dig('data', 'items') || []

    items.each do |item|
      identifier = item['identifier'].to_s
      next if identifier.empty?
      next if seen_identifiers[identifier]

      seen_identifiers[identifier] = true
      compartment_id = item['compartment-id'].to_s
      compartment_name = compartment_names_by_id[compartment_id] || 'Unknown'
      additional_details = item['additional-details']
      public_access_type = item['public-access-type'].to_s
      public_access_type = additional_details['publicAccessType'].to_s if public_access_type.empty? && additional_details.is_a?(Hash)

      findings << <<~ENTRY.chomp
        Bucket Name: #{item['display-name']}
        Identifier: #{identifier}
        Region: #{region}
        Compartment Name: #{compartment_name}
        Compartment ID: #{compartment_id}
        Public Access Type: #{public_access_type.empty? ? 'Unknown' : public_access_type}
        Issue: Bucket is publicly visible
      ENTRY
    end
  end

  numbered_findings = findings.each_with_index.map do |entry, index|
    "[#{index + 1}]\n#{entry}"
  end

  describe 'Object Storage buckets' do
    it 'should not be publicly visible' do
      expect(findings).to be_empty, <<~MSG
        Non-compliant findings:

        #{numbered_findings.join("\n\n")}
      MSG
    end
  end

  detector_recipe_ocid = input('detector_recipe_ocid')

  cloud_guard = cloud_guard_helper(tenancy_ocid: tenancy_ocid, detector_recipe_ocid: detector_recipe_ocid)
  cloud_guard_status = cloud_guard.status
  cloud_guard_rule_enabled = cloud_guard.detector_rule_enabled?(rule_id: 'BUCKET_IS_PUBLIC')

  describe 'Cloud Guard' do
    it 'is enabled' do
      expect(cloud_guard_status).to cmp 'ENABLED'
    end

    if cloud_guard_status == 'ENABLED'
      it 'detector rule "Bucket is public" is enabled' do
        expect(cloud_guard_rule_enabled).to cmp true
      end
    end
  end
end
