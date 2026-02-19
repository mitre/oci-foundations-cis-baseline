control 'oci-foundations-1.7' do
  title 'Ensure MFA is enabled for all users with a console password'

  desc <<~DESC
    Multi-factor authentication is a method of authentication that requires the use of more
    than one factor to verify a user’s identity. With MFA enabled in the IAM service, when a
    user signs in to Oracle Cloud Infrastructure, they are prompted for their user name and
    password, which is the first factor (something that they know). The user is then prompted
    to provide a verification code from a registered MFA device, which is the second factor
    (something that they have). The two factors work together, requiring an extra layer of
    security to verify the user’s identity and complete the sign-in process. OCI IAM supports
    two-factor authentication using a password (first factor) and a device that can generate a
    time-based one-time password (TOTP) (second factor). See OCI documentation for more
    details. Multi factor authentication adds an extra layer of security during the login
    process and makes it harder for unauthorized users to gain access to OCI resources.
  DESC

  desc 'check', <<~CHECK
    From Console: Go to Identity Domains: https://cloud.oracle.com/identity/domains/ Select

    the Compartment your Domain to review is in Click on the Domain to review Click on
    Security Click Sign-on policies Select the sign-on policy to review Under the sign-on
    rules header, click the three dots on the rule with the highest priority. Select Edit
    sign-on rule Verify that allow access is selected and prompt for an additional factor is
    enabled This requires users to enable MFA when they next login next however, to determine
    users have enabled MFA use the below CLI. From the CLI: This CLI command checks which
    users have enabled MFA for their accounts Execute the below: tenancy_ocid=`oci iam
    compartment list --raw-output --query
    "data[?contains(\"compartment-id\",'.tenancy.')].\"compartment-id\" | [0]"` for
    id_domain_url in `oci iam domain list --compartment-id $tenancy_ocid --all | jq -r
    '.data[] | .url'` do oci identity-domains users list --endpoint $id_domain_url 2>/dev/null
    | jq -r '.data.resources[] |
    select(."urn-ietf-params-scim-schemas-oracle-idcs-extension-mfa-user"."mfa-status"!="ENROLLED")'
    2>/dev/null | jq -r '.ocid' done for region in `oci iam region-subscription list | jq -r
    '.data[] | ."region-name"'`; do for compid in `oci iam compartment list
    --compartment-id-in-subtree TRUE --all 2>/dev/null | jq -r '.data[] | .id'` do for
    id_domain_url in `oci iam domain list --compartment-id $compid --region $region --all
    2>/dev/null | jq -r '.data[] | .url'` do oci identity-domains users list --endpoint
    $id_domain_url 2>/dev/null | jq -r '.data.resources[] |
    select(."urn-ietf-params-scim-schemas-oracle-idcs-extension-mfa-user"."mfa-status"!="ENROLLED")'
    2>/dev/null | jq -r '.ocid' done done done Ensure no results are returned
  CHECK

  desc 'fix', <<~FIX
    Each user must enable MFA for themselves using a device they will have access to every
    time they sign in. An administrator cannot enable MFA for another user but can enforce MFA
    by identifying the list of non-complaint users, notifying them or disabling access by
    resetting the password for non-complaint accounts. Disabling access from Console: Go to
    https://cloud.oracle.com/identity/ . Select Domains from Identity menu. Select the domain
    Click Security Click Sign-on polices then the "Default Sign-on Policy" Under the sign-on
    rules header, click the three dots on the rule with the highest priority. Select Edit
    sign-on rule Make a change to ensure that allow access is selected and prompt for an
    additional factor is enabled
  FIX

  impact 0.5

  tag severity: 'medium'
  tag benchmark_ref: '1.7'
  tag cis_level: 'Level 1'
  tag assessment_status: 'Automated'
  tag cis_controls: %w[6.3 6.5]

  tag cci: %w[CCI-000766]

  tag nist: ['IA-2']

  compartments_response = json(command: 'oci iam compartment list --include-root --compartment-id-in-subtree TRUE --all 2>/dev/null')
  compartments_data = compartments_response.params.fetch('data', [])
  compartment_ids = compartments_data.map { |compartment| compartment['id'] }.compact

  domain_by_url = {}

  compartment_ids.each do |compartment_id|
    domains_response = json(command: %(oci iam domain list --compartment-id "#{compartment_id}" --all))
    domains_data = domains_response.params.fetch('data', [])
    domains_data.each do |domain|
      domain_url = domain['url']
      next if domain_url.to_s.empty?

      domain_by_url[domain_url] = domain['display-name']
    end
  end

  non_compliant_users = []
  total_users = 0

  domain_by_url.each do |domain_url, domain_display_name|
    next if domain_url.to_s.empty?

    users_cmd = %(oci identity-domains users list --endpoint "#{domain_url}" --all)
    users_response = json(command: users_cmd).params
    users = users_response.dig('data', 'resources') || []

    users.each do |user|
      total_users += 1
      mfa_extension = user['urn-ietf-params-scim-schemas-oracle-idcs-extension-mfa-user'] || {}
      mfa_status = mfa_extension['mfa-status']

      next if mfa_status == 'ENROLLED'

      non_compliant_users << <<~ENTRY.chomp
        Username: #{user['user-name']}
        User OCID: #{user['ocid']}
        Domain Display Name: #{domain_display_name}
        Domain URL: #{domain_url}
        MFA Status: #{mfa_status}
      ENTRY
    end
  end

  if total_users.zero?
    impact 0.0
    describe 'OCI IAM users with console passwords' do
      skip 'No users found in tenancy.'
    end
  else
    numbered_findings = non_compliant_users.each_with_index.map do |entry, index|
      "[#{index + 1}]\n#{entry}"
    end

    describe 'OCI IAM users with console passwords' do
      it 'should have MFA status set to ENROLLED' do
        expect(non_compliant_users).to be_empty, <<~MSG
          Non-compliant findings:

          #{numbered_findings.join("\n\n")}
        MSG
      end
    end
  end
end
