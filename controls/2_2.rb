control '2_2' do
  title 'Ensure no security lists allow ingress from 0.0.0.0/0 to port 3389'

  desc <<~DESC
    Security lists provide stateful and stateless filtering of ingress and egress network
    traffic to OCI resources on a subnet level. It is recommended that no security group
    allows unrestricted ingress access to port 3389. Removing unfettered connectivity to
    remote console services, such as Remote Desktop Protocol (RDP), reduces a server's
    exposure to risk.
  DESC

  desc 'check', <<~CHECK
    From Console: Login into the OCI Console Click in the search bar at the top of the screen.

    Type Advanced Resource Query and hit enter . Click the Advanced Resource Query button in
    the upper right corner of the screen. Enter the following query in the query box: query
    SecurityList resources where (IngressSecurityRules.source = '0.0.0.0/0' &&
    IngressSecurityRules.protocol = 6 &&
    IngressSecurityRules.tcpOptions.destinationPortRange.max >= 3389 &&
    IngressSecurityRules.tcpOptions.destinationPortRange.min <= 3389) Ensure query returns no
    results. From CLI: Execute the following command: oci search resource structured-search
    --query-text "query SecurityList resources where (IngressSecurityRules.source =
    '0.0.0.0/0' && IngressSecurityRules.protocol = 6 &&
    IngressSecurityRules.tcpOptions.destinationPortRange.max >= 3389 &&
    IngressSecurityRules.tcpOptions.destinationPortRange.min <= 3389) " Ensure query returns
    no results. Cloud Guard To Enable Cloud Guard Auditing: Ensure Cloud Guard is enabled in
    the root compartment of the tenancy. For more information about enabling Cloud Guard,
    please look at the instructions included in Recommendation 3.15. From Console: Type Cloud
    Guard into the Search box at the top of the Console . Click Cloud Guard from the
    “Services” submenu. Click Detector Recipes in the Cloud Guard menu. Click OCI
    Configuration Detector Recipe (Oracle Managed) under the Recipe Name column. Find VCN
    Security list allows traffic to non-public port from all sources (0.0.0.0/0) in the
    Detector Rules column. Select the vertical ellipsis icon and choose Edit on the VCN
    Security list allows traffic to non-public port from all sources (0.0.0.0/0) row. In the
    Edit Detector Rule window find the Input Setting box and verify/add to the Restricted
    Protocol: Ports List setting to TCP:[3389], UDP:[3389]. Click the Save button. From CLI:

    Update the VCN Security list allows traffic to non-public port from all sources
    (0.0.0.0/0) Detector Rule in Cloud Guard to generate Problems if a VCN security list
    allows public access via port 3389 with the following command: oci cloud-guard
    detector-recipe-detector-rule update --detector-recipe-id <insert detector recipe ocid>
    --detector-rule-id SECURITY_LISTS_OPEN_SOURCE --details '{"configurations":[{ "configKey"
    : "securityListsOpenSourceConfig", "name" : "Restricted Protocol:Ports List", "value" :

    "TCP:[3389], UDP:[3389]", "dataType" : null, "values" : null }]}'
  CHECK

  desc 'fix', <<~FIX
    From Console: Follow the audit procedure above. For each security list in the returned

    results, click the security list name Either edit the ingress rule to be more restrictive,
    delete the ingress rule or click on the VCN and terminate the security list as
    appropriate. From CLI: Follow the audit procedure. For each of the security lists
    identified, execute the following command: oci network security-list get
    --security-list-id <security list id> Then either: Update the security list by copying the
    ingress-security-rules element from the JSON returned by the above command, edit it
    appropriately, and use it in the following command oci network security-list update
    --security-list-id <security-list-id> --ingress-security-rules '<ingress security rules
    JSON>' or Delete the security list with the following command: oci network security-list
    delete --security-list-id <security list id>
  FIX

  desc 'potential_impacts', <<~POTENTIAL_IMPACTS
    For updating an existing environment, care should be taken to ensure that administrators
    currently relying on an existing ingress from 0.0.0.0/0 have access to ports 22 and/or
    3389 through another network security group or security list.
  POTENTIAL_IMPACTS

  impact 0.5

  tag check_id: 'C-2_2'
  tag severity: 'medium'
  tag gid: 'CIS-2_2'
  tag rid: 'xccdf_cis_cis_rule_2_2'
  tag stig_id: '2.2'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag 'documentable'

  tag cci: [
    'CCI-001097',
    'CCI-001098',
    'CCI-002395',
    'CCI-002668',
    'CCI-002669',
    'CCI-001243',
    'CCI-001184',
    'CCI-000364',
    'CCI-000366',
    'CCI-000381'
  ]

  tag nist: [
    'SC-7 a',
    'SC-7 c',
    'SC-7 b',
    'SI-4 (11)',
    'SI-4 (13) (c)',
    'SI-3 c 2',
    'SC-23',
    'CM-6 a',
    'CM-6 b',
    'CM-7 a'
  ]

  cmd = %q{oci search resource structured-search --query-text "query SecurityList resources where (IngressSecurityRules.source = '0.0.0.0/0' && IngressSecurityRules.protocol = 6 && IngressSecurityRules.tcpOptions.destinationPortRange.max >= 3389 && IngressSecurityRules.tcpOptions.destinationPortRange.min <= 3389)"}
  json_output = json(command: cmd)
  output = json_output.params.dig('data', 'items')

  describe 'Ensure no security lists allow ingress from 0.0.0.0/0 to port 3389' do
    subject { output }
    it { should be_empty }
  end

  cloud_guard_check = input('cloud_guard_check')
  detector_recipe_ocid = input('detector_recipe_ocid')

  if cloud_guard_check
    tenancy_ocid = input('tenancy_ocid')
    cloud_guard = cloud_guard_helper(tenancy_ocid: tenancy_ocid, detector_recipe_ocid: detector_recipe_ocid)
    cloud_guard_status = cloud_guard.status
    cloud_guard_output = cloud_guard.detector_rule_value(rule_id: 'SECURITY_LISTS_OPEN_SOURCE', config_key: 'securityListsOpenSourceConfig')
    cloud_guard_rule_enabled = cloud_guard.detector_rule_enabled?(rule_id: 'SECURITY_LISTS_OPEN_SOURCE')
  end

  describe 'Cloud Guard' do
    if cloud_guard_check
      it 'is enabled' do
        expect(cloud_guard_status).to cmp 'ENABLED'
      end

      it 'detector rule "VCN Security list allows traffic to non-public port from all sources (0.0.0.0/0)" is enabled' do
        expect(cloud_guard_rule_enabled).to cmp true
      end

      it 'detector rule "VCN Security list allows traffic to non-public port from all sources (0.0.0.0/0)" includes TCP and UDP port 3389' do
        expect(cloud_guard.port_list_check?(config_value: cloud_guard_output, protocol: 'TCP', port: 3389)).to cmp true
        expect(cloud_guard.port_list_check?(config_value: cloud_guard_output, protocol: 'UDP', port: 3389)).to cmp true
      end
    else
      skip 'Cloud Guard check skipped. cloud_guard_check is set to false.'
    end
  end
end
