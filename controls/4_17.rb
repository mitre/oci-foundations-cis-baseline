control '4_17' do
  title 'Ensure write level Object Storage logging is enabled for all buckets'

  desc <<~DESC
    Object Storage write logs will log all write requests made to objects in a bucket.
    Enabling an Object Storage write log, the requestAction property would contain values of
    PUT , POST , or DELETE . This will provide you more visibility into changes to objects in
    your buckets.
  DESC

  desc 'check', <<~CHECK
    From Console: Log into the OCI console. Select Storage from the Services, and click on

    Buckets . Click on the individual Bucket under the Name heading. Click Logs from the
    Resource menu on the left. Click on the slider under Enable Log in row labeled Write
    Access Events . Select the Compartment. Select the Log Group. Enter a Log Name . Select a
    Log Retention. Click Enable Log . From CLI: Find the bucket name of the specific bucket.
    oci os bucket list --compartment-id <compartment-id> Find the OCID of the Log Group used
    for FlowLogs . oci logging log-group list --compartment-id <compartment-id> --query "data
    [?\"display-name\"=='<log-group-name>']" List the logs associated with the bucket name for
    this bucket oci logging log list --log-group-id <log-group-id> --query "data
    [?configuration.source.resource=='<bucket-name>']" Ensure a log is listed for this bucket
    name
  CHECK

  desc 'fix', <<~FIX
    From Console: First, if a log group for holding these logs has not already been created,

    create a log group by the following steps: Go to the Log Groups page Click the Create Log
    Groups button in the middle of the screen. Select the relevant compartment to place these
    logs. Type a name for the log group in the Name box. Add an optional description in the
    Description box. Click the Create button in the lower left-hand corner. Second, enable
    Object Storage write log logging for your bucket(s) by the following steps: Go to the Logs
    page https://cloud.oracle.com/logging/logs Click the Enable Service Log button in the
    middle of the screen. Select the relevant resource compartment. Select Object Storage from
    the Service drop down menu. Select the relevant bucket from the resource drop down menu.
    Select 'Write Access Events` from the Log Category drop down menu. Type a name for your
    Object Storage write log in the Log Name drop down menu. Click the Enable Log button in
    the lower left-hand corner. From CLI: First, if a log group for holding these logs has not
    already been created, create a log group by the following steps: Create a log group: oci
    logging log-group create --compartment-id <compartment-id> --display-name "<display-name>"
    --description "<description>" The output of the command gives you a work request id. You
    can query the work request to see the status of the job by issuing the following command:

    oci logging work-request get --work-request-id <work-request-id> Look for status filed to
    be SUCCEEDED . Second, enable Object Storage write log logging for your bucket(s) by the
    following steps: Get the Log group ID needed for creating the Log: oci logging log-group
    list --compartment-id <compartment-id> --query 'data[?contains("display-name",
    `'"<display-name>"'`)].id|join(`\n`, @)' --raw-output Create a JSON file called
    config.json with the following content: { "compartment-id":"<compartment-id>", "source": {
    "resource": "<bucket-name.", "service": "ObjectStorage", "source-type": "OCISERVICE",
    "category": "write" } } The compartment-id is the Compartment OCID of where the bucket is
    exists. The resource value is the bucket name. Create the Service Log: oci logging log
    create --log-group-id <log-group-id> --display-name "<display-name>" --log-type SERVICE
    --is-enabled TRUE --configuration file://config.json The output of the command gives you a
    work request id. You can query the work request to see that status of the job by issuing
    the following command: oci logging work-request get --work-request-id <work-request-id>
    Look for the status filed to be SUCCEEDED .
  FIX

  desc 'potential_impacts', <<~POTENTIAL_IMPACTS
    "There is no performance
  POTENTIAL_IMPACTS

  impact 0.5

  tag check_id: 'C-4_17'
  tag severity: 'medium'
  tag gid: 'CIS-4_17'
  tag rid: 'xccdf_cis_cis_rule_4_17'
  tag stig_id: '4.17'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag 'documentable'

  tag cci: [
    'CCI-000011',
    'CCI-002124',
    'CCI-002123',
    'CCI-002121',
    'CCI-000123',
    'CCI-000169',
    'CCI-000172',
    'CCI-000126'
  ]

  tag nist: [
    'AC-2 f',
    'AC-2 h 2',
    'AC-2 h 1',
    'AC-2 f',
    'AU-2 a',
    'AU-12 a',
    'AU-12 c',
    'AU-2 c'
  ]

  regions = json(command: 'oci iam region-subscription list --all').params.fetch('data', []).map { |region| region['region-name'] }.compact
  compartments = json(command: 'oci iam compartment list --include-root --compartment-id-in-subtree TRUE --all 2>/dev/null').params.fetch('data', []).map { |compartment| compartment['id'] }.compact

  buckets = []
  regions.each do |region|
    compartments.each do |compartment_id|
      buckets_response = json(
        command: %(oci os bucket list --compartment-id "#{compartment_id}" --region "#{region}" --all 2>/dev/null)
      )
      buckets_response.params.fetch('data', []).each do |bucket|
        buckets << bucket.merge('region' => region, 'compartment-id' => compartment_id)
      end
    end
  end

  if buckets.empty?
    impact 0.0
    describe 'Ensure write level Object Storage logging is enabled for all buckets' do
      skip 'No Object Storage buckets found in tenancy.'
    end
  else
    logs_by_resource = Hash.new { |hash, key| hash[key] = [] }

    regions.each do |region|
      compartments.each do |compartment_id|
        log_groups = json(
          command: %(oci logging log-group list --compartment-id "#{compartment_id}" --region "#{region}" --all 2>/dev/null)
        ).params.fetch('data', [])

        log_groups.each do |log_group|
          log_group_id = log_group['id'].to_s
          next if log_group_id.empty?

          logs = json(
            command: %(oci logging log list --log-group-id "#{log_group_id}" --log-type SERVICE --region "#{region}" --all 2>/dev/null)
          ).params.fetch('data', [])

          logs.each do |log|
            source = log.dig('configuration', 'source') || {}
            resource_name = source['resource'].to_s
            next if resource_name.empty?

            logs_by_resource["#{region}|#{resource_name}"] << log.merge('region' => region, 'log-group-id' => log_group_id)
          end
        end
      end
    end

    findings = []

    buckets.each do |bucket|
      bucket_name = bucket['name'].to_s
      bucket_region = bucket['region'].to_s
      bucket_logs = logs_by_resource["#{bucket_region}|#{bucket_name}"]

      enabled_logs = bucket_logs.select do |log|
        log['lifecycle-state'] == 'ACTIVE' && log['is-enabled'] == true
      end

      compliant_log = enabled_logs.any? do |log|
        source = log.dig('configuration', 'source') || {}
        service = source['service'].to_s.strip.downcase
        category = source['category'].to_s.strip.downcase
        service == 'objectstorage' && category == 'write'
      end

      next if compliant_log

      issue = if bucket_logs.empty?
                'No log found for bucket'
              elsif enabled_logs.empty?
                'Log found but not enabled or active'
              else
                'No enabled write log found for bucket'
              end

      findings << {
        'bucket_name' => bucket_name,
        'region' => bucket_region,
        'compartment_id' => bucket['compartment-id'],
        'issue' => issue
      }
    end

    describe 'Ensure write level Object Storage logging is enabled for all buckets' do
      subject { findings }
      it { should cmp [] }
    end
  end
end
