control '1_15' do
  title 'Ensure storage service-level admins cannot delete resources they manage.'

  desc <<~DESC
    To apply the separation of duties security principle, one can restrict service-level
    administrators from being able to delete resources they are managing. It means
    service-level administrators can only manage resources of a specific service but not
    delete resources for that specific service. Example policies for global/tenant level for
    block volume service-administrators: Allow group VolumeUsers to manage volumes in tenancy
    where request.permission!='VOLUME_DELETE' Allow group VolumeUsers to manage volume-backups
    in tenancy where request.permission!='VOLUME_BACKUP_DELETE' Example policies for
    global/tenant level for file storage system service-administrators: Allow group FileUsers
    to manage file-systems in tenancy where request.permission!='FILE_SYSTEM_DELETE' Allow
    group FileUsers to manage mount-targets in tenancy where
    request.permission!='MOUNT_TARGET_DELETE' Allow group FileUsers to manage export-sets in
    tenancy where request.permission!='EXPORT_SET_DELETE' Example policies for global/tenant
    level for object storage system service-administrators: Allow group BucketUsers to manage
    objects in tenancy where request.permission!='OBJECT_DELETE' Allow group BucketUsers to
    manage buckets in tenancy where request.permission!='BUCKET_DELETE' Creating service-level
    administrators without the ability to delete the resource they are managing helps in
    tightly controlling access to Oracle Cloud Infrastructure (OCI) services by implementing
    the separation of duties security principle.
  DESC

  desc 'check', <<~CHECK
    From Console: Login to OCI console. Go to Identity -> Policies, In the compartment

    dropdown, choose the compartment. Open each policy to view the policy statements. Verify
    the policies to ensure that the policy statements that grant access to storage
    service-level administrators have a condition that excludes access to delete the service
    they are the administrator for. From CLI: Execute the following command: for compid in
    `oci iam compartment list --compartment-id-in-subtree TRUE 2>/dev/null | jq -r '.data[] |
    .id'` do for policy in `oci iam policy list --compartment-id $compid 2>/dev/null | jq -r
    '.data[] | .id'` do output=`oci iam policy list --compartment-id $compid 2>/dev/null | jq
    -r '.data[] | .id, .name, .statements'` if [ ! -z "$output" ]; then echo $output; fi done
    done Verify the policies to ensure that the policy statements that grant access to storage
    service-level administrators have a condition that excludes access to delete the service
    they are the administrator for.
  CHECK

  desc 'fix', <<~FIX
    From Console: Login to OCI console. Go to Identity -> Policies, In the compartment

    dropdown, choose the compartment. Open each policy to view the policy statements. Add the
    appropriate where condition to any policy statement that allows the storage service-level
    to manage the storage service.
  FIX

  impact 0.5

  tag check_id: 'C-1_15'
  tag severity: 'medium'
  tag gid: 'CIS-1_15'
  tag rid: 'xccdf_cis_cis_rule_1_15'
  tag stig_id: '1.15'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag 'documentable'

  tag cci: [
    'CCI-000056',
    'CCI-000059',
    'CCI-000058',
    'CCI-002113',
    'CCI-002117',
    'CCI-002118',
    'CCI-002126',
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
    'AC-2 c',
    'AC-2 d 2',
    'AC-2 d 3',
    'AC-2 c'
  ]
end
