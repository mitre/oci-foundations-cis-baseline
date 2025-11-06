control '1_3' do
  title 'Ensure IAM administrators cannot update tenancy Administrators group'
  desc "Tenancy administrators can create more users, groups, and policies to provide other service administrators access to OCI resources. For example, an IAM administrator will need to have access to manage
resources like compartments, users, groups, dynamic-groups, policies, identity-providers, tenancy tag-namespaces, tag-definitions in the tenancy. The policy that gives IAM-Administrators or any other group full access to 'groups' resources should not allow access to the tenancy 'Administrators' group. The policy statements would look like - Allow group IAMAdmins to inspect users in tenancy
Allow group IAMAdmins to use users in tenancy where target.group.name != 'Administrators'
Allow group IAMAdmins to inspect groups in tenancy
Allow group IAMAdmins to use groups in tenancy where target.group.name != 'Administrators' Note: You must include separate statements for 'inspect' access, because the target.group.name variable is not used by the ListUsers and ListGroups operations

These policy statements ensure that no other group can manage tenancy administrator users or the membership to the 'Administrators' group thereby gain or remove tenancy administrator access."
  desc 'check', 'From CLI: Run the following OCI CLI commands providing the root_compartment_OCID oci iam policy list --compartment-id <root_compartment_OCID> | grep -i " to use users in tenancy"
oci iam policy list --compartment-id <root_compartment_OCID> | grep -i " to use groups in tenancy" Verify the results to ensure that the policy statements that grant access to use or manage users or groups in the tenancy have a condition that excludes access to Administrators group or to users in the Administrators group.'
  desc 'fix', "From Console: Login to OCI Console. Select Identity from Services Menu. Select Policies from Identity Menu. Click on an individual policy under the Name heading. Ensure Policy statements look like this - Allow group IAMAdmins to use users in tenancy where target.group.name != 'Administrators'
Allow group IAMAdmins to use groups in tenancy where target.group.name != 'Administrators'"
  impact 0.5
  tag check_id: 'C-1_3'
  tag severity: 'medium'
  tag gid: 'CIS-1_3'
  tag rid: 'xccdf_cis_cis_rule_1_3'
  tag stig_id: '1.3'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag 'documentable'
  tag cci: ['CCI-000213', 'CCI-000225', 'CCI-000036', 'CCI-001003', 'CCI-000213', 'CCI-000225', 'CCI-000036', 'CCI-001003', 'CCI-000364', 'CCI-000365', 'CCI-000366', 'CCI-000421', 'CCI-002113', 'CCI-002117', 'CCI-002118', 'CCI-002126', 'CCI-000051', 'CCI-002856', 'CCI-003205']
  tag nist: ['AC-3', 'AC-6', 'AC-5 a', 'MP-2', 'AC-3', 'AC-6', 'AC-5 a', 'MP-2', 'CM-6 a', 'CM-6 a', 'CM-6 b', 'CM-9 a', 'AC-2 c', 'AC-2 d 2', 'AC-2 d 3', 'AC-2 i 1', 'AC-8 a', 'CP-12', 'SA-12 (8)']
end
