control '1_17' do
  title 'Ensure there is only one active API Key for any single OCI IAM user'

  desc <<~DESC
    API Keys are long-term credentials for an OCI IAM user. They can be used to make
    programmatic requests to the OCI APIs directly or via, OCI SDKs or the OCI CLI. Having a
    single API Key for an OCI IAM reduces attack surface area and makes it easier to manage.
  DESC

  desc 'check', <<~CHECK
    %q{From Console: Login to OCI Console. Select Identity & Security from the Services menu.
    Select Users from the Identity menu. Click on an individual user under the Name heading.
    Click on API Keys in the lower left-hand corner of the page. Ensure the has only has a one
    API Key From CLI: Each user and in each Identity Domain oci raw-request --http-method GET
    --target-uri
    "https://<domain-endpoint>/admin/v1/ApiKeys?filter=user.ocid+eq+%<user-ocid>%22" | jq
    '.data.Resources[] | "\(.fingerprint) \(.id)"' Ensure only one key is returned}
  CHECK

  desc 'fix', <<~FIX
    From Console: Login to OCI Console. Select Identity & Security from the Services menu.
    
    Select Domains from the Identity menu. For each domain listed, click on the name and
    select Users. Click on an individual user under the Name heading. Click on API Keys in the
    lower left-hand corner of the page. Delete one of the API Keys From CLI: Follow the audit
    procedure above. For API Key ID to be removed execute the following command: oci
    identity-domains api-key delete –api-key-id <id> --endpoint <domain-endpoint>
  FIX

  desc 'potential_impacts', <<~POTENTIAL_IMPACTS
    Deletion of an OCI API Key will remove programmatic access to OCI APIs
  POTENTIAL_IMPACTS

  impact 0.5

  tag check_id: 'C-1_17'
  tag severity: 'medium'
  tag gid: 'CIS-1_17'
  tag rid: 'xccdf_cis_cis_rule_1_17'
  tag stig_id: '1.17'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag cci: '%w[CCI-000364 CCI-000365 CCI-000366 CCI-000421 CCI-001097 CCI-001098 CCI-002395'
  tag 'documentable'

  tag nist: [
    'CM-6 a',
    'CM-6 a',
    'CM-6 b',
    'CM-9 a',
    'SC-7 a',
    'SC-7 c',
    'SC-7 b',
    'AC-2 a',
    'AC-2 a',
    'AC-2 b'
  ]
end
