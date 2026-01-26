control '1_11' do
  title 'Ensure user IAM Database Passwords rotate within 90 days'

  desc <<~DESC
    Users can create and manage their database password in their IAM user profile and use that
    password to authenticate to databases in their tenancy. An IAM database password is a
    different password than an OCI Console password. Setting an IAM database password allows
    an authorized IAM user to sign in to one or more Autonomous Databases in their tenancy. An
    IAM database password is a different password than an OCI Console password. Setting an IAM
    database password allows an authorized IAM user to sign in to one or more Autonomous
    Databases in their tenancy. It is important to secure and rotate an IAM Database password
    90 days or less as it provides the same access the user would have a using a local
    database user.
  DESC

  desc 'check', <<~CHECK
    From Console: Login to OCI Console. Select Identity & Security from the Services menu.

    Select Users from the Identity menu. Click on an individual user under the Name heading.
    Click on Database Passwords in the lower left-hand corner of the page. Ensure the date of
    the Database Passwords under the Created column of the Database Passwords is no more than
    90 days From Console: Login to OCI Console. Select Identity & Security from the Services
    menu. Select Domains from the Identity menu. For each domain listed, click on the name and
    select Users . Click on an individual user under the Username heading. Click on Database
    Passwords in the lower left-hand corner of the page. Ensure the date of the Database
    Passwords under the Created column of the Database Password is no more than 90 days old.
  CHECK

  desc 'fix', <<~FIX
    OCI IAM with Identity Domains From Console: Login to OCI Console. Select Identity &
    Security from the Services menu. Select Domains from the Identity menu. For each domain
    listed, click on the name and select Users . Click on an individual user under the
    Username heading. Click on IAM Database Passwords in the lower left-hand corner of the
    page. Delete any Database Passwords with a date older than 90 days under the Created
    column of the Database Passwords.
  FIX

  impact 0.5

  tag check_id: 'C-1_11'
  tag severity: 'medium'
  tag gid: 'CIS-1_11'
  tag rid: 'xccdf_cis_cis_rule_1_11'
  tag stig_id: '1.11'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag 'documentable'

  tag cci: [
    'CCI-000364',
    'CCI-000365',
    'CCI-000366',
    'CCI-000421',
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
  stale_database_passwords = []
  total_database_passwords = 0
  domain_urls.uniq!

  domain_urls.each do |domain_url|
    next if domain_url.to_s.empty?

    users_cmd = %(oci identity-domains users list --endpoint "#{domain_url}" --all)
    users_response = json(command: users_cmd).params
    users = users_response.dig('data', 'resources') || []

    users.each do |user|
      user_ocid = user['ocid']
      user_name = user['user-name']

      database_passwords_cmd = %(oci identity-domains user-db-credentials list --endpoint "#{domain_url}" --all --filter 'user.ocid eq "#{user_ocid}"')
      database_passwords_response = json(command: database_passwords_cmd).params
      database_passwords = database_passwords_response.dig('data', 'resources') || []
      total_database_passwords += database_passwords.length

      database_passwords.each do |database_password|
        created_at = database_password.dig('meta', 'created')

        password_details = {
          'user_name' => user_name,
          'domain_url' => domain_url,
          'database_password_id' => database_password['id'],
          'user_ocid' => user_ocid,
          'created' => created_at
        }

        created_time = Time.parse(created_at.to_s).utc

        next unless created_time < cutoff_time

        age_days = ((now - created_time) / 86_400).floor
        stale_database_passwords << password_details.merge('age_days' => age_days)
      end
    end
  end

  if total_database_passwords.zero?
    impact 0.0
    describe 'Ensure user IAM Database Passwords rotate within 90 days' do
      skip 'No database passwords found in tenancy.'
    end
  else
    describe 'Ensure user IAM Database Passwords rotate within 90 days' do
      subject { stale_database_passwords }
      it { should cmp [] }
    end
  end
end
