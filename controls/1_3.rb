control '1_3' do
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

  tag check_id: 'C-1_3'
  tag severity: 'medium'
  tag gid: 'CIS-1_3'
  tag rid: 'xccdf_cis_cis_rule_1_3'
  tag stig_id: '1.3'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag 'documentable'

  tag cci: [
    'CCI-000213',
    'CCI-000225',
    'CCI-000036',
    'CCI-001003',
    'CCI-000213',
    'CCI-000225',
    'CCI-000036',
    'CCI-001003',
    'CCI-000364',
    'CCI-000365',
    'CCI-000366',
    'CCI-000421',
    'CCI-002113',
    'CCI-002117',
    'CCI-002118',
    'CCI-002126',
    'CCI-000051',
    'CCI-002856',
    'CCI-003205'
  ]

  tag nist: [
    'AC-3',
    'AC-6',
    'AC-5 a',
    'MP-2',
    'AC-3',
    'AC-6',
    'AC-5 a',
    'MP-2',
    'CM-6 a',
    'CM-6 a',
    'CM-6 b',
    'CM-9 a',
    'AC-2 c',
    'AC-2 d 2',
    'AC-2 d 3',
    'AC-2 i 1',
    'AC-8 a',
    'CP-12',
    'SA-12 (8)'
  ]

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
    it { should be_empty }
  end
end
