control '5_1_2' do
  title 'Ensure Object Storage Buckets are encrypted with a Customer Managed Key (CMK).'

  desc <<~DESC
    Oracle Object Storage buckets support encryption with a Customer Managed Key (CMK). By
    default, Object Storage buckets are encrypted with an Oracle managed key. Encryption of
    Object Storage buckets with a Customer Managed Key (CMK) provides an additional level of
    security on your data by allowing you to manage your own encryption key lifecycle
    management for the bucket.
  DESC

  desc 'check', <<~CHECK
    From Console: Go to https://cloud.oracle.com/object-storage/buckets Click on an individual

    bucket under the Name heading. Ensure that the Encryption Key is not set to Oracle managed
    key . Repeat for each compartment From CLI: Execute the following command oci os bucket
    get --bucket-name <bucket-name> Ensure kms-key-id is not null Cloud Guard To Enable Cloud
    Guard Auditing: Ensure Cloud Guard is enabled in the root compartment of the tenancy. For
    more information about enabling Cloud Guard, please look at the instructions included in
    Recommendation 3.15. From Console: Type Cloud Guard into the Search box at the top of the
    Console. Click Cloud Guard from the “Services” submenu. Click Detector Recipes in the
    Cloud Guard menu. Click OCI Configuration Detector Recipe (Oracle Managed) under the
    Recipe Name column. Find Object Storage bucket is encrypted with Oracle-managed key in the
    Detector Rules column. Verify that the Object Storage bucket is encrypted with
    Oracle-managed key Detector Rule is Enabled. From CLI: Verify the Object Storage bucket is
    encrypted with Oracle-managed key Detector Rule in Cloud Guard is enabled to generate
    Problems if Object Storage Buckets are configured without a customer managed key with the
    following command: oci cloud-guard detector-recipe-detector-rule get --detector-recipe-id
    <insert detector recipe ocid> --detector-rule-id BUCKET_ENCRYPTED_WITH_ORACLE_MANAGED_KEY
  CHECK

  desc 'fix', <<~FIX
    From Console: Go to https://cloud.oracle.com/object-storage/buckets Click on an individual

    bucket under the Name heading. Click Assign next to Encryption Key: Oracle managed key .
    Select a Vault Select a Master Encryption Key Click Assign From CLI: Execute the following
    command oci os bucket update --bucket-name <bucket-name> --kms-key-id
    <master-encryption-key-id>
  FIX

  desc 'potential_impacts', <<~POTENTIAL_IMPACTS
    [object Object]
  POTENTIAL_IMPACTS

  impact 0.5

  tag check_id: 'C-5_1_2'
  tag severity: 'medium'
  tag gid: 'CIS-5_1_2'
  tag rid: 'xccdf_cis_cis_rule_5_1_2'
  tag stig_id: '5.1.2'
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

  regions_response = json(command: 'oci iam region-subscription list --all')
  regions_data = regions_response.params.fetch('data', [])
  regions = regions_data.map { |region| region['region-name'] }.compact

  compartments_response = json(command: 'oci iam compartment list --include-root --compartment-id-in-subtree TRUE 2>/dev/null')
  compartments_data = compartments_response.params.fetch('data', [])
  compartments = compartments_data.map { |compartment| compartment['id'] }.compact

  buckets_missing_cmk = []

  regions.each do |region|
    compartments.each do |compartment_id|
      buckets_response = json(
        command: %(oci os bucket list --compartment-id "#{compartment_id}" --region "#{region}" 2>/dev/null)
      )
      buckets = buckets_response.params.fetch('data', [])

      buckets.each do |bucket|
        bucket_name = bucket['name']
        bucket_details = json(
          command: %(oci os bucket get --bucket-name "#{bucket_name}" --region "#{region}" 2>/dev/null)
        )
        kms_key_id = bucket_details.params.dig('data', 'kms-key-id')

        next unless kms_key_id.to_s.strip.empty?

        buckets_missing_cmk << {
          'name' => bucket_name,
          'region' => region
        }
      end
    end
  end

  describe 'Ensure Object Storage Buckets are encrypted with a Customer Managed Key (CMK)' do
    subject { buckets_missing_cmk }
    it { should be_empty }
  end

  cloud_guard_check = input('cloud_guard_check')
  detector_recipe_ocid = input('detector_recipe_ocid')

  if cloud_guard_check
    tenancy_ocid = input('tenancy_ocid')
    cloud_guard = cloud_guard_helper(tenancy_ocid: tenancy_ocid, detector_recipe_ocid: detector_recipe_ocid)
    cloud_guard_status = cloud_guard.status
    cloud_guard_rule_enabled = cloud_guard.detector_rule_enabled?(rule_id: 'BUCKET_ENCRYPTED_WITH_ORACLE_MANAGED_KEY')
  end

  describe 'Cloud Guard' do
    if cloud_guard_check
      it 'is enabled' do
        expect(cloud_guard_status).to cmp 'ENABLED'
      end

      it 'detector rule "Object Storage bucket is encrypted with Oracle-managed key" is enabled' do
        expect(cloud_guard_rule_enabled).to cmp true
      end
    else
      skip 'Cloud Guard check skipped. cloud_guard_check is set to false.'
    end
  end
end
