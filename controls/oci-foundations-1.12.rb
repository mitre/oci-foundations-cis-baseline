control 'oci-foundations-1.12' do
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

  tag severity: 'medium'
  tag benchmark_ref: '1.12'
  tag cis_level: 'Level 1'
  tag assessment_status: 'Automated'
  tag cis_controls: %w[5.4]

  tag cci: %w[CCI-002113]

  tag nist: ['AC-2']

  tenancy_ocid = input('tenancy_ocid')

  domains_response = json(command: %(oci iam domain list --compartment-id "#{tenancy_ocid}" --display-name "Default" --all))
  domains_data = domains_response.params.fetch('data', [])
  domain_urls = domains_data.map { |domain| domain['url'] }.compact

  admins_with_api_keys = []
  admin_user_count = 0
  domain_urls.uniq!

  domain_urls.each do |domain_url|
    next if domain_url.to_s.empty?

    groups_cmd = %(oci identity-domains groups list --endpoint "#{domain_url}" --all --filter 'displayName eq "Administrators"')
    groups_response = json(command: groups_cmd).params
    groups = groups_response.dig('data', 'resources') || []

    groups.each do |group|
      group_id = group['id']
      next if group_id.to_s.empty?

      users_cmd = %(oci identity-domains users list --endpoint "#{domain_url}" --all --filter 'groups.value eq "#{group_id}"')
      users_response = json(command: users_cmd).params
      users = users_response.dig('data', 'resources') || []

      users.each do |user|
        user_ocid = user['ocid']
        user_name = user['user-name']
        next if user_ocid.to_s.empty?

        admin_user_count += 1

        api_keys_cmd = %(oci identity-domains api-keys list --endpoint "#{domain_url}" --all --filter 'user.ocid eq "#{user_ocid}"')
        api_keys_response = json(command: api_keys_cmd).params
        api_keys = api_keys_response.dig('data', 'resources') || []

        api_keys.each do |api_key|
          admins_with_api_keys << <<~ENTRY.chomp
            Username: #{user_name}
            User OCID: #{user_ocid}
            API Key ID: #{api_key['id']}
            Domain URL: #{domain_url}
          ENTRY
        end
      end
    end
  end

  if admin_user_count.zero?
    impact 0.0
    describe 'Ensure API keys are not created for tenancy administrator users' do
      skip 'No Administrators group members found in the Default identity domain.'
    end
  else
    numbered_findings = admins_with_api_keys.each_with_index.map do |entry, index|
      "[#{index + 1}]\n#{entry}"
    end

    describe 'Tenancy administrator users' do
      it 'should not have API keys associated with their accounts' do
        expect(admins_with_api_keys).to be_empty, <<~MSG
          Non-compliant findings:

          #{numbered_findings.join("\n\n")}
        MSG
      end
    end
  end
end
