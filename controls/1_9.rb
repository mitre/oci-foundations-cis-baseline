control '1_9' do
  title 'Ensure user customer secret keys rotate every 90 days'

  desc <<~DESC
    Object Storage provides an API to enable interoperability with Amazon S3. To use this
    Amazon S3 Compatibility API, you need to generate the signing key required to authenticate
    with Amazon S3. This special signing key is an Access Key/Secret Key pair. Oracle
    generates the Customer Secret key to pair with the Access Key. It is important to rotate
    customer secret keys at least every 90 days, as they provide the same level of object
    storage access that the user they are associated with has.
  DESC

  desc 'check', <<~CHECK
    From Console: Login to OCI Console. Select Identity & Security from the Services menu.

    Select Domains from the Identity menu. For each domain listed, click on the name and
    select Users . Click on an individual user under the Username heading. Click on Customer
    Secret Keys in the lower left-hand corner of the page. Ensure the date of the Customer
    Secret Key under the Created column of the Customer Secret Key is no more than 90 days
    old.
  CHECK

  desc 'fix', <<~FIX
    From Console: Login to OCI Console. Select Identity & Security from the Services menu.

    Select Domains from the Identity menu. For each domain listed, click on the name and
    select Users . Click on an individual user under the Username heading. Click on Customer
    Secret Keys in the lower left-hand corner of the page. Delete any Access Keys with a date
    older than 90 days under the Created column of the Customer Secret Keys.
  FIX

  impact 0.5

  tag check_id: 'C-1_9'
  tag severity: 'medium'
  tag gid: 'CIS-1_9'
  tag rid: 'xccdf_cis_cis_rule_1_9'
  tag stig_id: '1.9'
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
  stale_customer_secret_keys = []
  total_customer_secret_keys = 0
  domain_urls.uniq!

  domain_urls.each do |domain_url|
    next if domain_url.to_s.empty?

    users_cmd = %(oci identity-domains users list --endpoint "#{domain_url}" --all)
    users_response = json(command: users_cmd).params
    users = users_response.dig('data', 'resources') || []

    users.each do |user|
      user_ocid = user['ocid']
      user_name = user['user-name']

      secret_keys_cmd = %(oci identity-domains customer-secret-keys list --endpoint "#{domain_url}" --all --filter 'user.ocid eq "#{user_ocid}"')
      secret_keys_response = json(command: secret_keys_cmd).params
      secret_keys = secret_keys_response.dig('data', 'resources') || []
      total_customer_secret_keys += secret_keys.length

      secret_keys.each do |secret_key|
        created_at = secret_key.dig('meta', 'created')

        key_details = {
          'user_name' => user_name,
          'domain_url' => domain_url,
          'customer_secret_key_id' => secret_key['ocid'],
          'user_ocid' => user_ocid,
          'created' => created_at
        }

        created_time = Time.parse(created_at.to_s).utc

        next unless created_time < cutoff_time

        age_days = ((now - created_time) / 86_400).floor
        stale_customer_secret_keys << key_details.merge('age_days' => age_days)
      end
    end
  end

  if total_customer_secret_keys.zero?
    impact 0.0
    describe 'Ensure user customer secret keys rotate every 90 days' do
      skip 'No customer secret keys found in tenancy.'
    end
  else
    describe 'Ensure user customer secret keys rotate every 90 days' do
      subject { stale_customer_secret_keys }
      it { should be_empty }
    end
  end
end
