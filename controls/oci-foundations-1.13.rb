control 'oci-foundations-1.13' do
  title 'Ensure all OCI IAM user accounts have a valid and current email address'

  desc <<~DESC
    All OCI IAM local user accounts have an email address field associated with the account.
    It is recommended to specify an email address that is valid and current. If you have an
    email address in your user profile, you can use the Forgot Password link on the sign on
    page to have a temporary password sent to you. Having a valid and current email address
    associated with an OCI IAM local user account allows you to tie the account to identity in
    your organization. It also allows that user to reset their password if it is forgotten or
    lost.
  DESC

  desc 'check', <<~CHECK
    From Console: Login to OCI Console. Select Identity & Security from the Services menu.

    Select Domains from the Identity menu. For each domain listed, click on the name and
    select Users . Click on an individual user under the Username heading. Ensure a valid and
    current email address is next to Email and Recovery email.
  CHECK

  desc 'fix', <<~FIX
    From Console: Login to OCI Console. Select Identity & Security from the Services menu.

    Select Domains from the Identity menu. For each domain listed, click on the name and
    select Users . Click on each non-complaint user. Click on Edit User . Enter a valid and
    current email address in the Email and Recovery Email text boxes. Click Save Changes
  FIX

  impact 0.5

  tag severity: 'medium'
  tag benchmark_ref: '1.13'
  tag cis_level: 'Level 1'
  tag assessment_status: 'Manual'
  tag cis_controls: %w[5.1]

  tag cci: %w[CCI-002110]

  tag nist: ['AC-2']

  compartments_response = json(command: 'oci iam compartment list --include-root --compartment-id-in-subtree TRUE --all 2>/dev/null')
  compartments_data = compartments_response.params.fetch('data', [])
  compartment_ids = compartments_data.map { |compartment| compartment['id'] }.compact

  domain_urls = []

  compartment_ids.each do |compartment_id|
    domains_response = json(command: %(oci iam domain list --compartment-id "#{compartment_id}" --all))
    domains_data = domains_response.params.fetch('data', [])
    domain_urls.concat(domains_data.map { |domain| domain['url'] }.compact)
  end

  users_without_valid_emails = []
  total_users = 0
  domain_urls.uniq!

  domain_urls.each do |domain_url|
    next if domain_url.to_s.empty?

    users_cmd = %(oci identity-domains users list --endpoint "#{domain_url}" --all)
    users_response = json(command: users_cmd).params
    users = users_response.dig('data', 'resources') || []

    users.each do |user|
      user_ocid = user['ocid']
      user_name = user['user-name']
      total_users += 1

      emails = user['emails'] || []

      has_verified_primary = emails.any? { |email| email['primary'] == true && email['verified'] == true }
      has_verified_recovery = emails.any? { |email| email['type'] == 'recovery' && email['verified'] == true }

      next if has_verified_primary && has_verified_recovery

      users_without_valid_emails << <<~ENTRY.chomp
        Username: #{user_name}
        User OCID: #{user_ocid}
        Domain URL: #{domain_url}
        Has Verified Primary: #{has_verified_primary}
        Has Verified Recovery: #{has_verified_recovery}
      ENTRY
    end
  end

  if total_users.zero?
    impact 0.0
    describe 'OCI IAM user accounts' do
      skip 'No users found in tenancy.'
    end
  else
    numbered_findings = users_without_valid_emails.each_with_index.map do |entry, index|
      "[#{index + 1}]\n#{entry}"
    end

    describe 'OCI IAM user accounts' do
      it 'should have verified primary and recovery email addresses' do
        expect(users_without_valid_emails).to be_empty, <<~MSG
          Users without valid email and recovery email:

          #{numbered_findings.join("\n\n")}
        MSG
      end
    end
  end
end
