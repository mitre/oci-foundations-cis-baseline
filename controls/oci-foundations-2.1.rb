control 'oci-foundations-2.1' do
  title 'Ensure no security lists allow ingress from 0.0.0.0/0 to port 22'

  desc <<~DESC
    Security lists provide stateful and stateless filtering of ingress and egress network
    traffic to OCI resources on a subnet level. It is recommended that no security list allows
    unrestricted ingress access to port 22. Removing unfettered connectivity to remote console
    services, such as Secure Shell (SSH), reduces a server's exposure to risk.
  DESC

  desc 'check', <<~CHECK
    From Console: Login to the OCI Console. Click the search bar at the top of the screen.

    Type Advanced Resource Query and hit enter . Click the Advanced Resource Query button in
    the upper right corner of the screen. Enter the following query in the query box: query
    SecurityList resources where (IngressSecurityRules.source = '0.0.0.0/0' &&
    IngressSecurityRules.protocol = 6 &&
    IngressSecurityRules.tcpOptions.destinationPortRange.max >= 22 &&
    IngressSecurityRules.tcpOptions.destinationPortRange.min =<= 22) Ensure the query returns
    no results. From CLI: Execute the following command: oci search resource structured-search
    --query-text "query SecurityList resources where (IngressSecurityRules.source =
    '0.0.0.0/0' && IngressSecurityRules.protocol = 6 &&
    IngressSecurityRules.tcpOptions.destinationPortRange.max >= 22 &&
    IngressSecurityRules.tcpOptions.destinationPortRange.min <= 22) " Ensure the query returns
    no results. Cloud Guard Ensure Cloud Guard is enabled in the root compartment of the
    tenancy. For more information about enabling Cloud Guard, please look at the instructions
    included in Recommendation 3.15. From Console: Type Cloud Guard into the Search box at the
    top of the Console. Click Cloud Guard from the “Services” submenu. Click Detector Recipes
    in the Cloud Guard menu. Click OCI Configuration Detector Recipe (Oracle Managed) under
    the Recipe Name column. Find VCN Security list allows traffic to non-public port from all
    sources (0.0.0.0/0) in the Detector Rules column. Select the vertical ellipsis icon and
    chose Edit on the VCN Security list allows traffic to non-public port from all sources
    (0.0.0.0/0) row. In the Edit Detector Rule window find the Input Setting box and
    verify/add to the Restricted Protocol: Ports List setting to TCP:[22], UDP:[22]. Click the
    Save button. From CLI: Update the VCN Security list allows traffic to non-public port from
    all sources (0.0.0.0/0) Detector Rule in Cloud Guard to generate Problems if a VCN
    security list allows public access via port 22 with the following command: oci cloud-guard
    detector-recipe-detector-rule update --detector-recipe-id <insert detector recipe ocid>
    --detector-rule-id SECURITY_LISTS_OPEN_SOURCE --details '{"configurations":[{ "configKey"
    : "securityListsOpenSourceConfig", "name" : "Restricted Protocol:Ports List", "value" :

    "TCP:[22], UDP:[22]", "dataType" : null, "values" : null }]}'
  CHECK

  desc 'fix', <<~FIX
    From Console: Follow the audit procedure above. For each security list in the returned

    results, click the security list name Either edit the ingress rule to be more restrictive,
    delete the ingress rule or click on the VCN and terminate the security list as
    appropriate. From CLI: Follow the audit procedure. For each of the security lists
    identified, execute the following command: oci network security-list get
    --security-list-id <security list id> Then either: Update the security list by copying the
    ingress-security-rules element from the JSON returned by the above command, edit it
    appropriately and use it in the following command: oci network security-list update
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

  tag severity: 'medium'
  tag benchmark_ref: '2.1'
  tag cis_level: 'Level 1'
  tag assessment_status: 'Automated'
  tag cis_controls: %w[4.4 12.3]

  tag cci: %w[CCI-001097 CCI-001184]

  tag nist: ['SC-7', 'SC-23']

  regions_response = json(command: 'oci iam region-subscription list --all')
  regions_data = regions_response.params.fetch('data', [])
  regions = regions_data.map { |region| region['region-name'] }.compact

  compartments_response = json(command: 'oci iam compartment list --include-root --compartment-id-in-subtree TRUE --all 2>/dev/null')
  compartments_data = compartments_response.params.fetch('data', [])
  compartment_ids = compartments_data.map { |compartment| compartment['id'] }.compact
  compartment_names_by_id = compartments_data.each_with_object({}) do |compartment, map|
    compartment_id = compartment['id'].to_s
    next if compartment_id.empty?

    map[compartment_id] = compartment['name']
  end

  findings = []

  regions.each do |region|
    compartment_ids.each do |compartment_id|
      security_lists_response = json(
        command: %(oci network security-list list --compartment-id "#{compartment_id}" --region "#{region}" --all 2>/dev/null)
      )
      security_lists = security_lists_response.params.fetch('data', [])

      security_lists.each do |security_list|
        security_list_id = security_list['id'].to_s
        next if security_list_id.empty?

        security_list_details_response = json(
          command: %(oci network security-list get --security-list-id "#{security_list_id}" --region "#{region}" 2>/dev/null)
        )
        security_list_details = security_list_details_response.params.fetch('data', {})
        ingress_rules = security_list_details['ingress-security-rules'] || []

        ingress_rules.each do |rule|
          next unless rule['source'] == '0.0.0.0/0'
          next unless rule['protocol'].to_s == '6'

          destination_port_range = rule.dig('tcp-options', 'destination-port-range')
          port_exposed = if destination_port_range.nil?
                           true
                         else
                           destination_port_range['min'].to_i <= 22 && destination_port_range['max'].to_i >= 22
                         end
          next unless port_exposed

          compartment_name = compartment_names_by_id[compartment_id] || 'Unknown'
          findings << <<~ENTRY.chomp
            Region: #{region}
            Compartment Name: #{compartment_name}
            Compartment ID: #{compartment_id}
            Security List Name: #{security_list['display-name']}
            Security List ID: #{security_list_id}
            Source: #{rule['source']}
            Destination Port Range: #{destination_port_range.nil? ? 'All TCP ports (none specified)' : "#{destination_port_range['min']}-#{destination_port_range['max']}"}
            Issue: Ingress from 0.0.0.0/0 allows port 22
          ENTRY
        end
      end
    end
  end

  numbered_findings = findings.each_with_index.map do |entry, index|
    "[#{index + 1}]\n#{entry}"
  end

  describe 'Security lists' do
    it 'should not allow ingress from 0.0.0.0/0 to port 22' do
      expect(findings).to be_empty, <<~MSG
        Non-compliant findings:

        #{numbered_findings.join("\n\n")}
      MSG
    end
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

      it 'detector rule "VCN Security list allows traffic to non-public port from all sources (0.0.0.0/0)" includes TCP and UDP port 22' do
        expect(cloud_guard.port_list_check?(config_value: cloud_guard_output, protocol: 'TCP', port: 22)).to cmp true
        expect(cloud_guard.port_list_check?(config_value: cloud_guard_output, protocol: 'UDP', port: 22)).to cmp true
      end
    else
      skip 'Cloud Guard check skipped. cloud_guard_check is set to false.'
    end
  end
end
