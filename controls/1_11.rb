control '1_11' do
  title 'Ensure user IAM Database Passwords rotate within 90 days'
  desc 'Users can create and manage their database password in their IAM user profile and use that password to authenticate to databases in their tenancy. An IAM database password is a different password than an OCI Console password. Setting an IAM database password allows an authorized IAM user to sign in to one or more Autonomous Databases in their tenancy. An IAM database password is a different password than an OCI Console password. Setting an IAM database password allows an authorized IAM user to sign in to one or more Autonomous Databases in their tenancy.

It is important to secure and rotate an IAM Database password 90 days or less as it provides the same access the user would have a using a local database user.'
  desc 'check', 'From Console: Login to OCI Console. Select Identity & Security from the Services menu. Select Users from the Identity menu. Click on an individual user under the Name heading. Click on Database Passwords in the lower left-hand corner of the page. Ensure the date of the Database Passwords under the Created column of the Database Passwords is no more than 90 days From Console: Login to OCI Console. Select Identity & Security from the Services menu. Select Domains from the Identity menu. For each domain listed, click on the name and select Users . Click on an individual user under the Username heading. Click on Database Passwords in the lower left-hand corner of the page. Ensure the date of the Database Passwords under the Created column of the Database Password is no more than 90 days old.'
  desc 'fix', 'OCI IAM with Identity Domains From Console: Login to OCI Console. Select Identity & Security from the Services menu. Select Domains from the Identity menu. For each domain listed, click on the name and select Users . Click on an individual user under the Username heading. Click on IAM Database Passwords in the lower left-hand corner of the page. Delete any Database Passwords with a date older than 90 days under the Created column of the Database Passwords.'
  desc 'mitigations', 'The Audit Procedure and Remediation Procedure for OCI IAM without Identity Domains can be found in the CIS OCI Foundation Benchmark 2.0.0 under the respective recommendations.'
  impact 0.5
  tag check_id: 'C-1_11'
  tag severity: 'medium'
  tag gid: 'CIS-1_11'
  tag rid: 'xccdf_cis_cis_rule_1_11'
  tag stig_id: '1.11'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag 'documentable'
  tag cci: ['CCI-000364', 'CCI-000365', 'CCI-000366', 'CCI-000421', 'CCI-000200', 'CCI-000199', 'CCI-000205', 'CCI-000204']
  tag nist: ['CM-6 a', 'CM-6 a', 'CM-6 b', 'CM-9 a', 'IA-5 (1) (e)', 'IA-5 (1) (d)', 'IA-5 (1) (a)', 'IA-5 (8)']
end
