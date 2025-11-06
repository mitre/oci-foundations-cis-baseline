control '5_1_1' do
  title 'Ensure no Object Storage buckets are publicly visible.'
  desc "A bucket is a logical container for storing objects.  It is associated with a single compartment that has policies that determine what action a user can perform on a bucket and on all the objects in the bucket.  By Default a newly created bucket is private. It is recommended that no bucket be publicly accessible.

Removing unfettered reading of objects in a bucket reduces an organization's exposure to data loss."
  desc 'check', %q(From Console: Login into the OCI Console Click in the search bar at the top of the screen. Type Advanced Resource Query and click enter . Click the Advanced Resource Query button in the upper right of the screen. Enter the following query in the query box: query
bucket resources
where 
	(publicAccessType == 'ObjectRead') || (publicAccessType == 'ObjectReadWithoutList') Ensure query returns no results From CLI: Execute the following command: oci search resource structured-search --query-text "query       
bucket resources
where 
(publicAccessType == 'ObjectRead') || (publicAccessType == 'ObjectReadWithoutList')" Ensure query returns no results Cloud Guard To Enable Cloud Guard Auditing:
Ensure Cloud Guard is enabled in the root compartment of the tenancy. For more information about enabling Cloud Guard, please look at the instructions included in Recommendation 3.15. From Console: Type Cloud Guard into the Search box at the top of the Console. Click Cloud Guard from the “Services” submenu. Click Detector Recipes in the Cloud Guard menu. Click OCI Configuration Detector Recipe (Oracle Managed) under the Recipe Name column. Find Bucket is public in the Detector Rules column. Verify that the Bucket is public Detector Rule is Enabled. From CLI: Verify the Bucket is public Detector Rule in Cloud Guard is enabled to generate Problems if Object Storage Buckets are configured to be accessible over the public Internet with the following command: oci cloud-guard detector-recipe-detector-rule get --detector-recipe-id <insert detector recipe ocid> --detector-rule-id BUCKET_IS_PUBLIC)
  desc 'fix', 'From Console: Follow the audit procedure above. For each bucket in the returned results, click the Bucket Display Name Click Edit Visibility Select Private Click Save Changes From CLI: Follow the audit procedure For each of the buckets identified, execute the following command: oci os bucket update --bucket-name <bucket-name> --public-access-type NoPublicAccess'
  desc 'potential_impacts', 'For updating an existing bucket, care should be taken to ensure objects in the bucket can be accessed through either IAM policies or pre-authenticated requests.'
  impact 0.5
  tag check_id: 'C-5_1_1'
  tag severity: 'medium'
  tag gid: 'CIS-5_1_1'
  tag rid: 'xccdf_cis_cis_rule_5_1_1'
  tag stig_id: '5.1.1'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag 'documentable'
  tag cci: ['CCI-000213', 'CCI-000225', 'CCI-000036', 'CCI-001003', 'CCI-000051', 'CCI-002856', 'CCI-003205']
  tag nist: ['AC-3', 'AC-6', 'AC-5 a', 'MP-2', 'AC-8 a', 'CP-12', 'SA-12 (8)']
end
