control 'oci-foundations-1.3' do
  title 'Ensure IAM administrators cannot update tenancy Administrators group'

  desc <<~DESC
    "Tenancy administrators can create more users, groups, and policies to provide other
    service administrators access to OCI resources. For example, an IAM administrator will
    need to have access to manage resources like compartments, users, groups, dynamic-groups,
    policies, identity-providers, tenancy
  DESC

  desc 'check', <<~CHECK
    From CLI: Run the following OCI CLI commands providing the root_compartment_OCID oci iam

    policy list --compartment-id <root_compartment_OCID> | grep -i " to use users in tenancy"
    oci iam policy list --compartment-id <root_compartment_OCID> | grep -i " to use groups in
    tenancy" Replace "use" with "manage" in the above commands to review manage statements as
    well. Verify the results to ensure that the policy statements that grant access to use or
    manage users or groups in the tenancy have a condition that excludes access to
    Administrators group or to users in the Administrators group.
  CHECK

  desc 'fix', <<~FIX
    From Console: Login to OCI Console. Select Identity from Services Menu. Select Policies

    from Identity Menu. Click on an individual policy under the Name heading. Ensure Policy
    statements look like this - Allow group IAMAdmins to use users in tenancy where
    target.group.name != 'Administrators' Allow group IAMAdmins to use groups in tenancy where
    target.group.name != 'Administrators'
  FIX

  impact 0.5

  tag severity: 'medium'
  tag benchmark_ref: '1.3'
  tag cis_level: 'Level 1'
  tag assessment_status: 'Automated'
  tag cis_controls: %w[3.3 5.4]

  tag cci: %w[CCI-000213 CCI-002113]

  tag nist: ['AC-3', 'AC-2']

  tenancy_ocid = input('tenancy_ocid')

  policies_response = json(command: %(oci iam policy list --compartment-id "#{tenancy_ocid}" --all 2>/dev/null))
  policies = policies_response.params.fetch('data', [])

  user_group_admin_statement_regex = /\ballow\b.+\bto\b.+\b(?:use|manage)\b\s+(?:users|groups)\s+in\s+tenancy\b/i
  has_exclusion_regex = /where\b.*\badministrators\b.*(?:!=|<>|\bnot\b|\bneq\b|\bnotin\b)|where\b.*(?:!=|<>|\bnot\b|\bneq\b|\bnotin\b).*\badministrators\b/i

  findings = []

  policies.each do |policy|
    policy_name = policy['name']
    policy_id = policy['id']

    Array(policy['statements']).each do |statement|
      normalized_statement = statement.to_s.strip
      next if normalized_statement.empty?
      next unless normalized_statement.match?(user_group_admin_statement_regex)
      next if normalized_statement.match?(has_exclusion_regex)

      findings << <<~ENTRY.chomp
        Policy Name: #{policy_name}
        Policy ID: #{policy_id}
        Statement: #{normalized_statement}
        Issue: Statement grants "use/manage users or groups in tenancy" without excluding Administrators.
      ENTRY
    end
  end

  numbered_findings = findings.each_with_index.map do |entry, index|
    "[#{index + 1}]\n#{entry}"
  end

  describe 'IAM user and group administration policy statements' do
    it 'should exclude Administrators group access from "use/manage users and groups in tenancy" statements' do
      expect(findings).to be_empty, <<~MSG
        Non-compliant findings:

        #{numbered_findings.join("\n\n")}
      MSG
    end
  end
end
