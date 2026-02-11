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

  users_with_multiple_api_keys = []
  total_users = 0

  compartments_response = json(command: 'oci iam compartment list --include-root --compartment-id-in-subtree TRUE --all 2>/dev/null')
  compartments_data = compartments_response.params.fetch('data', [])
  compartment_ids = compartments_data.map { |compartment| compartment['id'] }.compact

  domains = []

  compartment_ids.each do |compartment_id|
    domains_response = json(command: %(oci iam domain list --compartment-id "#{compartment_id}" --all))
    domains_data = domains_response.params.fetch('data', [])
    domains.concat(
      domains_data.map do |domain|
        { 'url' => domain['url'], 'name' => domain['display-name'] }
      end
    )
  end

  domains.reject! { |domain| domain['url'].to_s.empty? }
  domains.uniq! { |domain| domain['url'] }

  domains.each do |domain|
    domain_url = domain['url']
    domain_name = domain['name']

    users_cmd = %(oci identity-domains users list --endpoint "#{domain_url}" --all)
    users_response = json(command: users_cmd).params
    users = users_response.dig('data', 'resources') || []

    users.each do |user|
      user_ocid = user['ocid']
      user_name = user['user-name']
      total_users += 1

      api_keys_cmd = %(oci identity-domains api-keys list --endpoint "#{domain_url}" --filter 'user.ocid eq "#{user_ocid}"' --all)
      api_keys_response = json(command: api_keys_cmd).params
      api_keys = api_keys_response.dig('data', 'resources') || []

      next if api_keys.length <= 1

      users_with_multiple_api_keys << {
        'user_name' => user_name,
        'api_key_count' => api_keys.length,
        'user_ocid' => user_ocid,
        'domain_name' => domain_name,
        'domain_url' => domain_url
      }
    end
  end

  if total_users.zero?
    impact 0.0
    describe 'Ensure there is only one active API Key for any single OCI IAM user' do
      skip 'No users found in tenancy.'
    end
  else
    describe 'Ensure there is only one active API Key for any single OCI IAM user' do
      subject { users_with_multiple_api_keys }
      it { should cmp [] }
    end
  end
end
