control 'oci-foundations-4.13' do
  title 'Ensure VCN flow logging is enabled for all subnets'

  desc <<~DESC
    VCN flow logs record details about traffic that has been accepted or rejected based on the
    security list rule. Enabling VCN flow logs enables you to monitor traffic flowing within
    your virtual network and can be used to detect anomalous traffic.
  DESC

  desc 'check', <<~CHECK
    From Console (For Logging enabled Flow logs): Go to the Virtual Cloud Network (VCN) page (

    https://cloud.oracle.com/networking/vcns ) Select the Compartment Click on the name of
    each VCN Click on each subnet within the VCN Under Resources click on Logs or the
    Monitoring tab Verify that there is a log enabled for the subnet Click the Log Name Verify
    Flowlogs Capture Filter is set to No filter (collecting all logs) If there is a Capture
    filter click the 'Capture Filter Name' Click Edit Verify Sampling rate is 100% Click
    Cancel Verify there is a in the Rules list that is: Enabled, Traffic disposition: All,
    Include/Exclude: Include, Source CIDR: Any, Destination CIDR: Any, IP Protocol: All From
    Console (For Network Command Center Enabled Flow logs): Go to the Network Command Center
    page ( https://cloud.oracle.com/networking/network-command-center ) Click on Flow Logs
    Click on the Flow log Name Click Edit Verify Sampling rate is 100% Click Cancel Verify
    there is a in the Rules list that is: Enabled, Traffic disposition: All, Include/Exclude:

    Include, Source CIDR: Any, Destination CIDR: Any, IP Protocol: All
  CHECK

  desc 'fix', <<~FIX
    From Console: First, if a Capture filter has not already been created, create a Capture

    Filter by the following steps: Go to the Network Command Center page (
    https://cloud.oracle.com/networking/network-command-center ) Click 'Capture filters' Click
    'Create Capture filter' Type a name for the Capture filter in the Name box. Select 'Flow
    log capture filter' For Sample rating select 100% Scroll to Rules For Traffic disposition
    select All For Include/Exclude select Include Level Source IPv4 CIDR or IPv6 prefix and
    Destination IPv4 CIDR or IPv6 prefix empty For IP protocol select Include Click Create
    Capture filter Second, enable VCN flow logging for your VCN or subnet(s) by the following
    steps: Go to the Logs page ( https://cloud.oracle.com/logging/logs ) Click the Enable
    Service Log button in the middle of the screen. Select the relevant resource compartment.
    Select Virtual Cloud Networks - Flow logs from the Service drop down menu. Select the
    relevant resource level from the resource drop down menu either VCN or subnet . Select the
    relevant resource from the resource drop down menu. Select the from the Log Category drop
    down menu that either Flow Logs - subnet records or Flow Logs - vcn records . Select the
    Capture filter from above Type a name for your flow logs in the Log Name text box. Select
    the Compartment for the Log Location Select the Log Group for the Log Location or Click
    Create New Group to create a new log group Click the Enable Log button in the lower
    left-hand corner.
  FIX

  desc 'potential_impacts', <<~POTENTIAL_IMPACTS
    Enabling VCN flow logs will not affect the performance of your virtual network but it will
    generate additional use of object storage that should be controlled via object lifecycle
    management. By default, VCN flow logs are stored for 30 days in object storage. Users can
    specify a longer retention period.
  POTENTIAL_IMPACTS

  impact 0.5

  tag severity: 'medium'
  tag benchmark_ref: '4.13'
  tag cis_level: 'Level 2'
  tag assessment_status: 'Automated'
  tag cis_controls: %w[8.2 8.5 13.6]

  tag cci: %w[CCI-000123 CCI-000130 CCI-001253]

  tag nist: ['AU-2', 'AU-3', 'SI-4']

  regions = json(command: 'oci iam region-subscription list --all').params.fetch('data', []).map { |region| region['region-name'] }.compact
  compartments = json(command: 'oci iam compartment list --include-root --compartment-id-in-subtree TRUE --all 2>/dev/null').params.fetch('data', []).map { |compartment| compartment['id'] }.compact

  findings = []
  any_resource = false

  regions.each do |region|
    compartments.each do |compartment_id|
      subnets = json(command: %(oci network subnet list --compartment-id "#{compartment_id}" --region "#{region}" --all 2>/dev/null)).params.fetch('data', []).select { |subnet| subnet['lifecycle-state'] == 'AVAILABLE' }

      next if subnets.empty?

      any_resource = true
      log_groups = json(command: %(oci logging log-group list --compartment-id "#{compartment_id}" --region "#{region}" --all 2>/dev/null)).params.fetch('data', [])

      logs = log_groups.flat_map do |log_group|
        json(command: %(oci logging log list --log-group-id "#{log_group['id']}" --log-type SERVICE --region "#{region}" --all 2>/dev/null)).params.fetch('data', [])
      end

      capture_filters = json(command: %(oci network capture-filter list --compartment-id "#{compartment_id}" --region "#{region}" --all 2>/dev/null)).params.fetch('data', [])

      compliant_filter_ids = capture_filters.select do |capture_filter|
        rules = capture_filter['flow-log-capture-filter-rules'] || []
        capture_filter['filter-type'].to_s.upcase == 'FLOWLOG' &&
          capture_filter['lifecycle-state'] == 'AVAILABLE' &&
          rules.any? do |rule|
            source_cidr = rule['source-cidr'].to_s.strip
            destination_cidr = rule['destination-cidr'].to_s.strip
            protocol = rule['protocol'].to_s.strip
            rule['is-enabled'] == true &&
              rule['flow-log-type'].to_s.strip.upcase == 'ALL' &&
              rule['rule-action'].to_s.strip.upcase == 'INCLUDE' &&
              (source_cidr.empty? || source_cidr == '0.0.0.0/0') &&
              (destination_cidr.empty? || destination_cidr == '0.0.0.0/0') &&
              (protocol.empty? || protocol.casecmp('all').zero?) &&
              rule['sampling-rate'].to_i == 1
          end
      end
      compliant_filter_ids = compliant_filter_ids.map { |capture_filter| capture_filter['id'] }.compact

      compliant_resources = logs.select do |log|
        capture_filter_id = log.dig('configuration', 'source', 'parameters', 'capture_filter').to_s
        log['lifecycle-state'] == 'ACTIVE' &&
          log['is-enabled'] == true &&
          compliant_filter_ids.include?(capture_filter_id)
      end
      compliant_resources = compliant_resources.map { |log| log.dig('configuration', 'source', 'resource').to_s }.reject(&:empty?)

      subnets.each do |subnet|
        subnet_id = subnet['id'].to_s
        vcn_id = subnet['vcn-id'].to_s
        covered = compliant_resources.include?(subnet_id) || compliant_resources.include?(vcn_id)
        next if covered

        findings << {
          'subnet_name' => subnet['display-name'],
          'subnet_id' => subnet_id,
          'vcn_id' => vcn_id,
          'region' => region,
          'compartment_id' => compartment_id,
          'issue' => 'No enabled flow log with compliant capture filter found for subnet or parent VCN'
        }
      end
    end
  end

  if !any_resource
    impact 0.0
    describe 'Ensure VCN flow logging is enabled for all subnets' do
      skip 'No subnets found in tenancy.'
    end
  else
    describe 'Ensure VCN flow logging is enabled for all subnets' do
      subject { findings }
      it { should cmp [] }
    end
  end
end
