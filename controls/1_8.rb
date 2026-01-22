control '1_8' do
  title 'Ensure user API keys rotate within 90 days'

  desc <<~DESC
    API keys are used by administrators, developers, services and scripts for accessing OCI
    APIs directly or via SDKs/OCI CLI to search, create, update or delete OCI resources. The
    API key is an RSA key pair. The private key is used for signing the API requests and the
    public key is associated with a local or synchronized user's profile. It is important to
    secure and rotate an API key every 90 days or less as it provides the same level of access
    that a user it is associated with has. In addition to a security engineering best
    practice, this is also a compliance requirement. For example, PCI-DSS Section 3.6.4
    states, "Verify that key-management procedures include a defined cryptoperiod for each key
    type in use and define a process for key changes at the end of the defined crypto
    period(s)."
  DESC

  desc 'check', <<~CHECK
    From Console: Login to OCI Console. Select Identity & Security from the Services menu.

    Select Domains from the Identity menu. For each domain listed, click on the name and
    select Users . Click on an individual user under the Name heading. Click on API Keys in
    the lower left-hand corner of the page. Ensure the date of the API key under the Created
    column of the API Key is no more than 90 days old.
  CHECK

  desc 'fix', <<~FIX
    From Console: Login to OCI Console. Select Identity & Security from the Services menu.

    Select Domains from the Identity menu. For each domain listed, click on the name and
    select Users . Click on an individual user under the Name heading. Click on API Keys in
    the lower left-hand corner of the page. Delete any API Keys that are older than 90 days
    under the Created column of the API Key table. From CLI: oci iam user api-key delete
    --user-id _<user_ocid>_ --fingerprint <fingerprint_of_the_key_to_be_deleted>
  FIX

  impact 0.5

  tag check_id: 'C-1_8'
  tag severity: 'medium'
  tag gid: 'CIS-1_8'
  tag rid: 'xccdf_cis_cis_rule_1_8'
  tag stig_id: '1.8'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag 'documentable'

  tag cci: [
    'CCI-000364',
    'CCI-000365',
    'CCI-000366',
    'CCI-000421',
    'CCI-001097',
    'CCI-001098',
    'CCI-002395',
    'CCI-002110',
    'CCI-002111',
    'CCI-002112',
    'CCI-000012',
    'CCI-000200',
    'CCI-000199',
    'CCI-000205',
    'CCI-000204'
  ]

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
    'AC-2 b',
    'AC-2 j',
    'IA-5 (1) (e)',
    'IA-5 (1) (d)',
    'IA-5 (1) (a)',
    'IA-5 (8)'
  ]

  require 'time'

  compartments_response = json(command: 'oci iam compartment list --include-root --compartment-id-in-subtree TRUE --all 2>/dev/null')
  compartments_data = compartments_response.params.fetch('data', [])
  compartment_ids = compartments_data.map { |compartment| compartment['id'] }.compact

  domain_urls = []

  compartment_ids.each do |compartment_id|
    domains_response = json(command: %(oci iam domain list --compartment-id "#{compartment_id}" --all))
    domains_data = domains_response.params.fetch('data', [])
    domain_urls.concat(domains_data.map { |domain| domain['url'] }.compact)
  end

  now = Time.now.utc
  cutoff_time = now - (90 * 24 * 60 * 60)
  stale_api_keys = []
  total_api_keys = 0
  domain_urls.uniq!

  domain_urls.each do |domain_url|
    next if domain_url.to_s.empty?

    users_cmd = %(oci identity-domains users list --endpoint "#{domain_url}" --all)
    users_response = json(command: users_cmd).params
    users = users_response.dig('data', 'resources') || []

    users.each do |user|
      user_ocid = user['ocid']
      user_name = user['user-name']

      api_keys_cmd = %(oci identity-domains api-keys list --endpoint "#{domain_url}" --all --filter 'user.ocid eq "#{user_ocid}"')
      api_keys_response = json(command: api_keys_cmd).params
      api_keys = api_keys_response.dig('data', 'resources') || []
      total_api_keys += api_keys.length

      api_keys.each do |api_key|
        created_at = api_key.dig('meta', 'created')

        key_details = {
          'user_name' => user_name,
          'domain_url' => domain_url,
          'api_key_id' => api_key['ocid'],
          'user_ocid' => user_ocid,
          'created' => created_at
        }

        created_time = Time.parse(created_at.to_s).utc

        next unless created_time < cutoff_time

        age_days = ((now - created_time) / 86_400).floor
        stale_api_keys << key_details.merge('age_days' => age_days)
      end
    end
  end

  if total_api_keys.zero?
    impact 0.0
    describe 'Ensure user API keys rotate within 90 days' do
      skip 'No API keys found in tenancy.'
    end
  else
    describe 'Ensure user API keys rotate within 90 days' do
      subject { stale_api_keys }
      it { should be_empty }
    end
  end
end
