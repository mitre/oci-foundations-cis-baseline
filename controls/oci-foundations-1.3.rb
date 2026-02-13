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

  cmd_users = "oci iam policy list --compartment-id '#{tenancy_ocid}' | grep -i ' to use users in tenancy' | jq -nR '[inputs]'"
  cmd_groups = "oci iam policy list --compartment-id '#{tenancy_ocid}' | grep -i ' to use groups in tenancy' | jq -nR '[inputs]'"

  users_output = json(command: cmd_users)
  users_params = users_output.params

  groups_output = json(command: cmd_groups)
  groups_params = groups_output.params

  policy_statements = [users_params, groups_params].flatten.compact.map { |policy| policy.to_s.strip }.reject(&:empty?)

  exclusion_regex = /where .*target\.group\.name\s*!=\s*['"]?Administrators['"]?/i
  non_excluded_policies = policy_statements.reject { |policy| policy.match?(exclusion_regex) }

  describe 'Ensure IAM administrators cannot update tenancy Administrators group' do
    subject { non_excluded_policies }
    it { should cmp [] }
  end
end
