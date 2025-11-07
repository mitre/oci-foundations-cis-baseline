control '1_12' do
  title 'Ensure API keys are not created for tenancy administrator users'

  desc <<~DESC
    Tenancy administrator users have full access to the organization's OCI tenancy. API keys
    associated with user accounts are used for invoking the OCI APIs via custom programs or
    clients like CLI/SDKs. The clients are typically used for performing day-to-day operations
    and should never require full tenancy access. Service-level administrative users with API
    keys should be used instead. For performing day-to-day operations tenancy administrator
    access is not needed. Service-level administrative users with API keys should be used to
    apply privileged security principle.
  DESC

  desc 'check', <<~CHECK
    From Console: Login to OCI Console. Select Identity & Security from the Services menu.
    
    Select Domains from the Identity menu. Click on the 'Default' Domain in the (root). Click
    on 'Groups'. Select the 'Administrators' group by clicking on the Name Click on each local
    or synchronized Administrators member profile Click on API Keys to verify if a user has an
    API key associated.
  CHECK

  desc 'fix', <<~FIX
    From Console: Login to OCI console. Select Identity from Services menu. Select Users from
    
    Identity menu, or select Domains , select a domain, and select Users . Select the username
    of a tenancy administrator user with an API key. Select API Keys from the menu in the
    lower left-hand corner. Delete any associated keys from the API Keys table. Repeat steps
    3-6 for all tenancy administrator users with an API key. From CLI: For each tenancy
    administrator user with an API key, execute the following command to retrieve API key
    details: oci iam user api-key list --user-id <user_id> For each API key, execute the
    following command to delete the key: oci iam user api-key delete --user-id <user_id>
    --fingerprint <api_key_fingerprint> The following message will be displayed: Are you sure
    you want to delete this resource? [y/N]: Type 'y' and press 'Enter'.
  FIX

  impact 0.5

  tag check_id: 'C-1_12'
  tag severity: 'medium'
  tag gid: 'CIS-1_12'
  tag rid: 'xccdf_cis_cis_rule_1_12'
  tag stig_id: '1.12'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag 'documentable'

  tag cci: [
    'CCI-000056',
    'CCI-000059',
    'CCI-000058',
    'CCI-002113',
    'CCI-002117',
    'CCI-002118',
    'CCI-002126'
  ]

  tag nist: [
    'AC-11 b',
    'AC-11 a',
    'AC-11 a',
    'AC-2 c',
    'AC-2 d 2',
    'AC-2 d 3',
    'AC-2 i 1'
  ]
end
