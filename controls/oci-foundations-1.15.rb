control 'oci-foundations-1.15' do
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

  tag severity: 'medium'
  tag benchmark_ref: '1.15'
  tag cis_level: 'Level 2'
  tag assessment_status: 'Manual'
  tag cis_controls: %w[5.4 6.8]

  tag cci: %w[CCI-002113]

  tag nist: ['AC-2']

  cmd = <<~CMD
    (
      for compid in `oci iam compartment list --include-root --compartment-id-in-subtree TRUE 2>/dev/null | jq -r '.data[] | .id'`
      do
        oci iam policy list --compartment-id "$compid" --all 2>/dev/null | jq -c '.data[]'
      done
    ) | jq -s '.'
  CMD

  json_output = json(command: cmd)

  policies = json_output.params || []

  storage_resources = %w[volumes volume-backups file-systems mount-targets export-sets objects buckets]
  violations = []

  policies.each do |policy|
    statements = policy['statements'] || []
    statements.each do |statement|
      stmt = statement.to_s.downcase

      next unless stmt.match?(/allow\s+.*\s+to\s+.*manage\s+.*?(#{storage_resources.join('|')})\b/)

      has_condition = stmt.include?('where')
      has_delete_exclusion = stmt.match?(/request\.permission\s*!=\s*['"][^'"]*_delete['"]/)

      next if has_condition && has_delete_exclusion

      violations << <<~ENTRY.chomp
        Policy: #{policy['name'] || policy['id']}
        Statement: #{statement}
      ENTRY
    end
  end

  numbered_findings = violations.each_with_index.map do |entry, index|
    "[#{index + 1}]\n#{entry}"
  end

  describe 'Storage service-level administrator policy statements' do
    it 'should include a delete-permission exclusion condition' do
      expect(violations).to be_empty, <<~MSG
        Non-compliant findings:

        #{numbered_findings.join("\n\n")}
      MSG
    end
  end
end
