control 'oci-foundations-5.1.3' do
  title 'Ensure Versioning is Enabled for Object Storage Buckets'

  desc <<~DESC
    A bucket is a logical container for storing objects. Object versioning is enabled at the
    bucket level and is disabled by default upon creation. Versioning directs Object Storage
    to automatically create an object version each time a new object is uploaded, an existing
    object is overwritten, or when an object is deleted. You can enable object versioning at
    bucket creation time or later. Versioning object storage buckets provides for additional
    integrity of your data. Management of data integrity is critical to protecting and
    accessing protected data. Some customers want to identify object storage buckets without
    versioning in order to apply their own data lifecycle protection and management policy.
  DESC

  desc 'check', <<~CHECK
    From Console: Login to OCI Console. Select Storage from the Services menu. Select Buckets

    from under the Object Storage & Archive Storage section. Click on an individual bucket
    under the Name heading. Ensure that the Object Versioning is set to Enabled. Repeat for
    each compartment From CLI: Execute the following command: for region in $(oci iam
    region-subscription list --all | jq -r '.data[] | ."region-name"') do echo "Enumerating
    region $region" for compid in $(oci iam compartment list --include-root
    --compartment-id-in-subtree TRUE 2>/dev/null | jq -r '.data[] | .id') do echo "Enumerating
    compartment $compid" for bkt in $(oci os bucket list --compartment-id $compid --region
    $region 2>/dev/null | jq -r '.data[] | .name') do output=$(oci os bucket get --bucket-name
    $bkt --region $region 2>/dev/null | jq -r '.data | select(."versioning" ==
    "Disabled").name') if [ ! -z "$output" ]; then echo $output; fi done done done Ensure no
    results are returned.
  CHECK

  desc 'fix', <<~FIX
    From Console: Follow the audit procedure above. For each bucket in the returned results,

    click the Bucket Display Name Click Edit next to Object Versioning: Disabled Click Enable
    Versioning From CLI: Follow the audit procedure For each of the buckets identified,
    execute the following command: oci os bucket update --bucket-name <bucket name>
    --versioning Enabled
  FIX

  impact 0.5

  tag severity: 'medium'
  tag benchmark_ref: '5.1.3'
  tag cis_level: 'Level 2'
  tag assessment_status: 'Automated'

  tag cci: %w[CCI-000537]

  tag nist: ['CP-9']

  regions_response = json(command: 'oci iam region-subscription list --all')
  regions_data = regions_response.params.fetch('data', [])
  regions = regions_data.map { |region| region['region-name'] }.compact

  compartments_response = json(command: 'oci iam compartment list --include-root --compartment-id-in-subtree TRUE --all 2>/dev/null')
  compartments_data = compartments_response.params.fetch('data', [])
  compartment_ids = compartments_data.map { |compartment| compartment['id'] }.compact
  compartment_names_by_id = compartments_data.each_with_object({}) do |compartment, map|
    compartment_id = compartment['id'].to_s
    next if compartment_id.empty?

    map[compartment_id] = compartment['name']
  end

  findings = []
  total_buckets = 0

  regions.each do |region|
    compartment_ids.each do |compartment_id|
      buckets_response = json(
        command: %(oci os bucket list --compartment-id "#{compartment_id}" --region "#{region}" --all 2>/dev/null)
      )
      buckets = buckets_response.params.fetch('data', [])

      buckets.each do |bucket|
        bucket_name = bucket['name'].to_s
        next if bucket_name.empty?

        total_buckets += 1

        bucket_details_response = json(
          command: %(oci os bucket get --bucket-name "#{bucket_name}" --region "#{region}" 2>/dev/null)
        )
        bucket_details = bucket_details_response.params.fetch('data', {})
        versioning = bucket_details['versioning'].to_s
        next if versioning.casecmp('Enabled').zero?

        compartment_name = compartment_names_by_id[compartment_id] || 'Unknown'
        findings << <<~ENTRY.chomp
          Bucket Name: #{bucket_name}
          Region: #{region}
          Compartment Name: #{compartment_name}
          Compartment ID: #{compartment_id}
          Versioning: #{versioning.empty? ? 'Unknown' : versioning}
          Issue: Bucket versioning is not enabled
        ENTRY
      end
    end
  end

  if total_buckets.zero?
    impact 0.0
    describe 'Ensure Versioning is Enabled for Object Storage Buckets' do
      skip 'No Object Storage buckets found in tenancy.'
    end
  else
    numbered_findings = findings.each_with_index.map do |entry, index|
      "[#{index + 1}]\n#{entry}"
    end

    describe 'Object Storage buckets' do
      it 'should have versioning enabled' do
        expect(findings).to be_empty, <<~MSG
          Non-compliant findings:

          #{numbered_findings.join("\n\n")}
        MSG
      end
    end
  end
end
