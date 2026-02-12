control 'oci-foundations-1.17' do
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

  tag severity: 'medium'
  tag benchmark_ref: '1.17'
  tag cis_level: 'Level 1'
  tag assessment_status: 'Automated'
  tag cis_controls: %w[5]

  tag cci: %w[CCI-000015]

  tag nist: ['AC-2']

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

      users_with_multiple_api_keys << <<~ENTRY.chomp
        Username: #{user_name}
        API Key Count: #{api_keys.length}
        User OCID: #{user_ocid}
        Domain Name: #{domain_name}
        Domain URL: #{domain_url}
      ENTRY
    end
  end

  if total_users.zero?
    impact 0.0
    describe 'Ensure there is only one active API Key for any single OCI IAM user' do
      skip 'No users found in tenancy.'
    end
  else
    numbered_findings = users_with_multiple_api_keys.each_with_index.map do |entry, index|
      "[#{index + 1}]\n#{entry}"
    end

    describe 'OCI IAM users with API keys' do
      it 'should have at most one active API key' do
        expect(users_with_multiple_api_keys).to be_empty, <<~MSG
          Non-compliant findings:

          #{numbered_findings.join("\n\n")}
        MSG
      end
    end
  end
end
