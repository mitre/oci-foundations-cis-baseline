control '1_14' do
  title 'Ensure Instance Principal authentication is used for OCI instances, OCI Cloud Databases and OCI Functions to access OCI resources.'
  desc 'OCI instances, OCI database and OCI functions can access other OCI resources either via an OCI API key associated to a user or via Instance Principal.  Instance Principal authentication can be achieved by inclusion in a Dynamic Group that has an IAM policy granting it the required access or using an OCI IAM policy that has request.principal added to the where clause. Access to OCI Resources refers to making API calls to another OCI resource like Object Storage, OCI Vaults, etc.

Instance Principal reduces the risks related to hard-coded credentials.  Hard-coded API keys can be shared and require rotation, which can open them up to being compromised. Compromised credentials could allow access to OCI services outside of the expected radius.'
  desc 'check', "From Console (Dynamic Groups): Go to https://cloud.oracle.com/identity/domains/ Select a Compartment Click on a Domain Click on Dynamic groups Click on the Dynamic Group Check if the Matching Rules includes the instances accessing your OCI resources. From Console (request.principal): Go to https://cloud.oracle.com/identity/policies Select a Compartment Click on an individual policy under the Name heading. Ensure Policy statements look like this : allow any-user to <verb> <resource> in compartment <compartment-name> where ALL {request.principal.type='<resource_type>', request.principal.id='<resource_ocid>'} or allow any-user to <verb> <resource> in compartment <compartment-name> where ALL {request.principal.type='<resource_type>', request.principal.compartment.id='<compartment_OCID>'} From CLI (request.principal): Execute the following for each compartment_OCID: oci iam policy list --compartment-id <compartment_OCID> | grep request.principal Ensure that the condition includes the instances accessing your OCI resources"
  desc 'fix', 'From Console (Dynamic Groups): Go to https://cloud.oracle.com/identity/domains/ Select a Compartment Click on the Domain Click on Dynamic groups Click Create Dynamic Group. Enter a Name Enter a Description Enter Matching Rules to that includes the instances accessing your OCI resources. Click Create.'
  desc 'mitigations', 'The Audit Procedure and Remediation Procedure for OCI IAM without Identity Domains can be found in the CIS OCI Foundation Benchmark 2.0.0 under the respective recommendations.'
  desc 'potential_impacts', 'For an OCI instance that contains embedded credential audit the scripts and environment variables to ensure that none of them contain OCI API Keys or credentials.'
  impact 0.5
  tag check_id: 'C-1_14'
  tag severity: 'medium'
  tag gid: 'CIS-1_14'
  tag rid: 'xccdf_cis_cis_rule_1_14'
  tag stig_id: '1.14'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag 'documentable'
  tag cci: ['CCI-002113', 'CCI-002117', 'CCI-002118', 'CCI-000008', 'CCI-000051', 'CCI-002856', 'CCI-003205']
  tag nist: ['AC-2 c', 'AC-2 d 2', 'AC-2 d 3', 'AC-2 c', 'AC-8 a', 'CP-12', 'SA-12 (8)']
end
