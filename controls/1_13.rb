control '1_13' do
  title 'Ensure all OCI IAM user accounts have a valid and current email address'
  desc 'All OCI IAM local user accounts have an email address field associated with the account.  It is recommended to specify an email address that is valid and current. If you have an email address in your user profile, you can use the Forgot Password link on the sign on page to have a temporary password sent to you.

Having a valid and current email address associated with an OCI IAM local user account allows you to tie the account to identity in your organization.  It also allows that user to reset their password if it is forgotten or lost.'
  desc 'check', 'From Console: Login to OCI Console. Select Identity & Security from the Services menu. Select Domains from the Identity menu. For each domain listed, click on the name and select Users . Click on an individual user under the Username heading. Ensure a valid and current email address is next to Email and Recovery email.'
  desc 'fix', 'From Console: Login to OCI Console. Select Identity & Security from the Services menu. Select Domains from the Identity menu. For each domain listed, click on the name and select Users . Click on each non-complaint user. Click on Edit User . Enter a valid and current email address in the Email and Recovery Email text boxes. Click Save Changes'
  desc 'mitigations', 'The Audit Procedure and Remediation Procedure for OCI IAM without Identity Domains can be found in the CIS OCI Foundation Benchmark 2.0.0 under the respective recommendations.'
  impact 0.5
  tag check_id: 'C-1_13'
  tag severity: 'medium'
  tag gid: 'CIS-1_13'
  tag rid: 'xccdf_cis_cis_rule_1_13'
  tag stig_id: '1.13'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag 'documentable'
  tag cci: ['CCI-002110', 'CCI-002111', 'CCI-002112', 'CCI-000012', 'CCI-001054', 'CCI-001058', 'CCI-001060', 'CCI-001059', 'CCI-001057']
  tag nist: ['AC-2 a', 'AC-2 a', 'AC-2 b', 'AC-2 j', 'RA-5 a', 'RA-5 c', 'RA-5 d', 'RA-5 d', 'RA-5 b 1']
end
