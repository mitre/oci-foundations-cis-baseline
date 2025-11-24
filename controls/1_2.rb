control '1_2' do
  title 'Ensure permissions on all resources are given only to the tenancy administrator group'

  desc <<~DESC
    There is a built-in OCI IAM policy enabling the Administrators group to perform any action
    within a tenancy. In the OCI IAM console, this policy reads: Allow group Administrators to
    manage all-resources in tenancy Administrators create more users, groups, and policies to
    provide appropriate access to other groups. Administrators should not allow
    any-other-group full access to the tenancy by writing a policy like this - Allow group
    any-other-group to manage all-resources in tenancy The access should be narrowed down to
    ensure the least-privileged principle is applied. Permission to manage all resources in a
    tenancy should be limited to a small number of users in the Administrators group for
    break-glass situations and to set up users/groups/policies when a tenancy is created. No
    group other than Administrators in a tenancy should need access to all resources in a
    tenancy, as this violates the enforcement of the least privilege principle.
  DESC

  desc 'check', <<~CHECK
    From CLI: Run OCI CLI command providing the root compartment OCID to get the list of

    groups having access to manage all resources in your tenancy. oci iam policy list
    --compartment-id <root_compartment_OCID> | grep -i "to manage all-resources in tenancy"
    Verify the results to ensure only the Administrators group has access to manage all
    resources in tenancy. "Allow group Administrators to manage all-resources in tenancy"
  CHECK

  desc 'fix', <<~FIX
    From Console: Login to OCI console. Go to Identity -> Policies , In the compartment

    dropdown, choose the root compartment. Open each policy to view the policy statements.
    Remove any policy statement that allows any group other than Administrators or any service
    access to manage all resources in the tenancy. From CLI: The policies can also be updated
    via OCI CLI, SDK and API, with an example of the CLI commands below: Delete a policy via
    the CLI: oci iam policy delete --policy-id <policy-ocid> Update a policy via the CLI: oci
    iam policy update --policy-id <policy-ocid> --statements <json-array-of-statements> Note:

    You should generally not delete the policy that allows the Administrators group the
    ability to manage all resources in the tenancy.
  FIX

  impact 0.5

  tag check_id: 'C-1_2'
  tag severity: 'medium'
  tag gid: 'CIS-1_2'
  tag rid: 'xccdf_cis_cis_rule_1_2'
  tag stig_id: '1.2'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag 'documentable'

  tag cci: [
    'CCI-000213',
    'CCI-000225',
    'CCI-000036',
    'CCI-001003',
    'CCI-000051',
    'CCI-002856',
    'CCI-003205'
  ]

  tag nist: [
    'AC-3',
    'AC-6',
    'AC-5 a',
    'MP-2',
    'AC-8 a',
    'CP-12',
    'SA-12 (8)'
  ]
end
