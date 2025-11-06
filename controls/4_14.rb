control '4_14' do
  title 'Ensure Cloud Guard is enabled in the root compartment of the tenancy'
  desc 'Cloud Guard detects misconfigured resources and insecure activity within a tenancy and provides security administrators with the visibility to resolve these issues. Upon detection, Cloud Guard can suggest, assist, or take corrective actions to mitigate these issues. Cloud Guard should be enabled in the root compartment of your tenancy with the default configuration, activity detectors and responders.

Cloud Guard provides an automated means to monitor a tenancy for resources that are configured in an insecure manner as well as risky network activity from these resources.'
  desc 'check', %q(From Console: Type Cloud Guard into the Search box at the top of the Console. Click Cloud Guard from the "Services" submenu. View if Cloud Guard is enabled From CLI: Retrieve the Cloud Guard status from the console oci cloud-guard configuration get --compartment-id <tenancy-ocid> --query 'data.status' Ensure the returned value is "ENABLED"`)
  desc 'fix', %q(From Console: Type Cloud Guard into the Search box at the top of the Console. Click Cloud Guard from the "Services" submenu. Click Enable Cloud Guard . Click Create Policy . Click Next . Under Reporting Region , select a region. Under Compartments To Monitor , choose Select Compartment . Under Select Compartments , select the root compartment. Under Configuration Detector Recipe , select OCI Configuration Detector Recipe (Oracle Managed) . Under Activity Detector Recipe , select OCI Activity Detector Recipe (Oracle Managed) . Click Enable . From CLI: Create OCI IAM Policy for Cloud Guard oci iam policy create --compartment-id '<tenancy-id>' --name 'CloudGuardPolicies' --description 'Cloud Guard Access Policy' --statements '[
    "allow service cloudguard to read vaults in tenancy",
    "allow service cloudguard to read keys in tenancy",
    "allow service cloudguard to read compartments in tenancy",
    "allow service cloudguard to read tenancies in tenancy",
    "allow service cloudguard to read audit-events in tenancy",
    "allow service cloudguard to read compute-management-family in tenancy",
    "allow service cloudguard to read instance-family in tenancy",
    "allow service cloudguard to read virtual-network-family in tenancy",
    "allow service cloudguard to read volume-family in tenancy",
    "allow service cloudguard to read database-family in tenancy",
    "allow service cloudguard to read object-family in tenancy",
    "allow service cloudguard to read load-balancers in tenancy",
    "allow service cloudguard to read users in tenancy",
    "allow service cloudguard to read groups in tenancy",
    "allow service cloudguard to read policies in tenancy",
    "allow service cloudguard to read dynamic-groups in tenancy",
    "allow service cloudguard to read authentication-policies in tenancy"
    ]' Enable Cloud Guard in root compartment oci cloud-guard configuration update --reporting-region '<region-name>' --compartment-id '<tenancy-id>' --status 'ENABLED')
  desc 'potential_impacts', 'There is no performance impact when enabling the above described features, but additional IAM policies will be required.'
  impact 0.5
  tag check_id: 'C-4_14'
  tag severity: 'medium'
  tag gid: 'CIS-4_14'
  tag rid: 'xccdf_cis_cis_rule_4_14'
  tag stig_id: '4.14'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag 'documentable'
  tag cci: ['CCI-000011', 'CCI-002124', 'CCI-002123', 'CCI-002121', 'CCI-000123', 'CCI-000169', 'CCI-000172', 'CCI-000126', 'CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000172', 'CCI-000133', 'CCI-000134', 'CCI-001875', 'CCI-000135']
  tag nist: ['AC-2 f', 'AC-2 h 2', 'AC-2 h 1', 'AC-2 f', 'AU-2 a', 'AU-12 a', 'AU-12 c', 'AU-2 c', 'AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-12 c', 'AU-3 d', 'AU-3 e', 'AU-7 a', 'AU-3 (1)']
end
