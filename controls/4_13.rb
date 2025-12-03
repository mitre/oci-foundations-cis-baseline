control '4_13' do
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

  tag check_id: 'C-4_13'
  tag severity: 'medium'
  tag gid: 'CIS-4_13'
  tag rid: 'xccdf_cis_cis_rule_4_13'
  tag stig_id: '4.13'
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
    'CCI-000126',
    'CCI-000130',
    'CCI-000131',
    'CCI-000132',
    'CCI-000172',
    'CCI-002110',
    'CCI-002111',
    'CCI-002122',
    'CCI-001253',
    'CCI-002641',
    'CCI-001255',
    'CCI-002654'
  ]

  tag nist: [
    'AC-2 f',
    'AC-2 h 2',
    'AC-2 h 1',
    'AC-2 f',
    'AU-2 a',
    'AU-12 a',
    'AU-12 c',
    'AU-2 c',
    'AU-3 a',
    'AU-3 b',
    'AU-3 c',
    'AU-12 c',
    'AC-2 a',
    'AC-2 a',
    'AC-2 g',
    'SI-4 a 1',
    'SI-4 a 1',
    'SI-4 c 1',
    'SI-4 g'
  ]

  describe 'Ensure VCN flow logging is enabled for all subnets' do
    skip 'The check for this control needs to be done manually'
  end
end
