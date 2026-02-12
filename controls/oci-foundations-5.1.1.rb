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

  cmd = %q{oci search resource structured-search --query-text "query bucket resources where (publicAccessType == 'ObjectRead') || (publicAccessType == 'ObjectReadWithoutList')"}
  json_output = json(command: cmd)
  output = json_output.params.dig('data', 'items')

  describe 'Ensure no Object Storage buckets are publicly visible' do
    subject { output }
    it { should cmp [] }
  end

  cloud_guard_check = input('cloud_guard_check')
  detector_recipe_ocid = input('detector_recipe_ocid')

  if cloud_guard_check
    tenancy_ocid = input('tenancy_ocid')
    cloud_guard = cloud_guard_helper(tenancy_ocid: tenancy_ocid, detector_recipe_ocid: detector_recipe_ocid)
    cloud_guard_status = cloud_guard.status
    cloud_guard_rule_enabled = cloud_guard.detector_rule_enabled?(rule_id: 'BUCKET_IS_PUBLIC')
  end

  describe 'Cloud Guard' do
    if cloud_guard_check
      it 'is enabled' do
        expect(cloud_guard_status).to cmp 'ENABLED'
      end

      it 'detector rule "Bucket is public" is enabled' do
        expect(cloud_guard_rule_enabled).to cmp true
      end
    else
      skip 'Cloud Guard check skipped. cloud_guard_check is set to false.'
    end
  end
end
