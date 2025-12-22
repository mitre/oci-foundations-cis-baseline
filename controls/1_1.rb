control '1_1' do
  title 'Ensure service level admins are created to manage resources of particular service'

  desc <<~DESC
    To apply least-privilege security principle, one can create service-level administrators in
    corresponding groups and assigning specific users to each service-level administrative group
    in a tenancy. This limits administrative access in a tenancy. It means service-level
    administrators can only manage resources of a specific service.

    Example policies for global/tenant level service-administrators:
      - Allow group VolumeAdmins to manage volume-family in tenancy
      - Allow group ComputeAdmins to manage instance-family in tenancy
      - Allow group NetworkAdmins to manage virtual-network-family in tenancy

    A tenancy with identity domains:
    An Identity Domain is a container of users, groups, Apps and other security configurations.
    A tenancy that has Identity Domains available comes seeded with a 'Default' identity domain.

    If a group belongs to a domain different than the default domain, use a domain prefix in
    the policy statements.
  DESC

  desc 'check', <<~CHECK
    From CLI:
    Set up OCI CLI with an IAM administrator user who has read access to IAM resources such as
    groups and policies. Run OCI CLI command providing the root_compartment_OCID.

    Get the list of groups in a tenancy:
      oci iam group list --compartment-id <root_compartment_OCID> | grep name

    Note: A tenancy with identity domains - The above CLI commands work with the default identity
    domain only. For IaaS resource management, users and groups created in the default domain are
    sufficient.

    Ensure distinct administrative groups are created as per your organization's definition of
    service-administrators. Verify the appropriate policies are created for the service-administrators
    groups to have the right access to the corresponding services.

    Retrieve the policy statements scoped at the tenancy level and/or per compartment:
      oci iam policy list --compartment-id <root_compartment_OCID> | grep "in tenancy"
      oci iam policy list --compartment-id <root_compartment_OCID> | grep "in compartment"

    The --compartment-id parameter can be changed to a child compartment to get policies
    associated with child compartments:
      oci iam policy list --compartment-id <child_compartment_OCID> | grep "in compartment"

    Verify the results to ensure the right policies are created for service-administrators to
    have the necessary access.
  CHECK

  desc 'fix', <<~FIX
    Refer to the policy syntax document and create new policies if the audit results indicate
    that the required policies are missing.

    This can be done via OCI console or OCI CLI/SDK or API.

    Creating a new policy from CLI:
      oci iam policy create [OPTIONS]

    This creates a new policy in the specified compartment (either the tenancy or another of
    your compartments). If you're new to policies, see Getting Started with Policies.

    You must specify:
      - A name for the policy (unique across all policies in your tenancy, cannot be changed)
      - A description for the policy (can be empty, can be changed with UpdatePolicy)
      - One or more policy statements in the statements array

    For information about writing policies, see How Policies Work and Common Policies.
  FIX

  impact 0.5

  tag check_id: 'C-1_1'
  tag severity: 'medium'
  tag gid: 'CIS-1_1'
  tag rid: 'xccdf_cis_cis_rule_1_1'
  tag stig_id: '1.1'
  tag gtitle: '<GroupDescription></GroupDescription>'

  tag cci: [
    'CCI-000056',
    'CCI-000059',
    'CCI-000058',
    'CCI-002113',
    'CCI-002117',
    'CCI-002118',
    'CCI-002126',
    'CCI-001682',
    'CCI-000766',
    'CCI-001643',
    'CCI-000011',
    'CCI-002113',
    'CCI-002117',
    'CCI-002118',
    'CCI-000008'
  ]

  tag nist: [
    'AC-11 b',
    'AC-11 a',
    'AC-11 a',
    'AC-2 c',
    'AC-2 d 2',
    'AC-2 d 3',
    'AC-2 i 1',
    'AC-2 (2)',
    'IA-2 (2)',
    'RA-5 a',
    'AC-2 f',
    'AC-2 c',
    'AC-2 d 2',
    'AC-2 d 3',
    'AC-2 c'
  ]

  tenancy_ocid = input('tenancy_ocid')

  cmd_groups = "oci iam group list --compartment-id '#{tenancy_ocid}' | jq -r '.data[].name'"
  groups = command(cmd_groups).stdout

  cmd_policies = "oci iam policy list --compartment-id '#{tenancy_ocid}' | jq -r '.data[].statements[]' | grep -i 'manage.*-family in'"
  policies = command(cmd_policies).stdout

  describe 'Ensure service level admins are created to manage resources of particular service' do
    it 'should have service-level admin groups and manage policies' do
      expect(groups).to match(/admin/i)
      expect(policies).to match(/manage.*(instance|volume|virtual-network|database|object)-family in (tenancy|compartment)/i)
    end
  end
end
