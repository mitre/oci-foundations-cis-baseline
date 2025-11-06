control '5_1_2' do
  title 'Ensure Object Storage Buckets are encrypted with a Customer Managed Key (CMK).'
  desc 'Oracle Object Storage buckets support encryption with a Customer Managed Key (CMK).  By default, Object Storage buckets are encrypted with an Oracle managed key.

Encryption of Object Storage buckets with a Customer Managed Key (CMK) provides an additional level of security on your data by allowing you to manage your own encryption key lifecycle management for the bucket.'
  desc 'check', 'From Console: Go to https://cloud.oracle.com/object-storage/buckets Click on an individual bucket under the Name heading. Ensure that the Encryption Key is not set to Oracle managed key . Repeat for each compartment From CLI: Execute the following command oci os bucket get --bucket-name <bucket-name> Ensure kms-key-id is not null Cloud Guard To Enable Cloud Guard Auditing:
Ensure Cloud Guard is enabled in the root compartment of the tenancy. For more information about enabling Cloud Guard, please look at the instructions included in Recommendation 3.15. From Console: Type Cloud Guard into the Search box at the top of the Console. Click Cloud Guard from the “Services” submenu. Click Detector Recipes in the Cloud Guard menu. Click OCI Configuration Detector Recipe (Oracle Managed) under the Recipe Name column. Find Object Storage bucket is encrypted with Oracle-managed key in the Detector Rules column. Verify that the Object Storage bucket is encrypted with Oracle-managed key Detector Rule is Enabled. From CLI: Verify the Object Storage bucket is encrypted with Oracle-managed key Detector Rule in Cloud Guard is enabled to generate Problems if Object Storage Buckets are configured without a customer managed key with the following command: oci cloud-guard detector-recipe-detector-rule get --detector-recipe-id <insert detector recipe ocid> --detector-rule-id BUCKET_ENCRYPTED_WITH_ORACLE_MANAGED_KEY'
  desc 'fix', 'From Console: Go to https://cloud.oracle.com/object-storage/buckets Click on an individual bucket under the Name heading. Click Assign next to Encryption Key: Oracle managed key . Select a Vault Select a Master Encryption Key Click Assign From CLI: Execute the following command oci os bucket update --bucket-name <bucket-name> --kms-key-id <master-encryption-key-id>'
  desc 'potential_impacts', '[object Object]'
  impact 0.5
  tag check_id: 'C-5_1_2'
  tag severity: 'medium'
  tag gid: 'CIS-5_1_2'
  tag rid: 'xccdf_cis_cis_rule_5_1_2'
  tag stig_id: '5.1.2'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag cci: ['CCI-001199', 'CCI-002472', 'CCI-000183', 'CCI-000051', 'CCI-002856', 'CCI-003205']
  tag nist: ['SC-28', 'SC-28', 'IA-5 g', 'AC-8 a', 'CP-12', 'SA-12 (8)']
end
