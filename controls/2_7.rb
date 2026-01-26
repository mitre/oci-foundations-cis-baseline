control '2_7' do
  title 'Ensure Oracle Analytics Cloud (OAC) access is restricted to allowed sources or deployed within a Virtual Cloud Network.'

  desc <<~DESC
    Oracle Analytics Cloud (OAC) is a scalable and secure public cloud service that provides a
    full set of capabilities to explore and perform collaborative analytics for you, your
    workgroup, and your enterprise. OAC instances provide ingress filtering of network traffic
    or can be deployed with in an existing Virtual Cloud Network VCN. It is recommended that
    all new OAC instances be deployed within a VCN and that the Access Control Rules are
    restricted to your corporate IP Addresses or VCNs for existing OAC instances. Restricting
    connectivity to Oracle Analytics Cloud instances reduces an OAC instance’s exposure to
    risk.
  DESC

  desc 'check', <<~CHECK
    From Console: 1 Login into the OCI Console 2. Click in the search bar, top of the screen.

    3. Type Advanced Resource Query and hit enter. 4. Click the Advanced Resource Query button
    in the upper right of the screen. 5. Enter the following query in the query box: query
    analyticsinstance resources For each OAC Instance returned click on the link under Display
    name . Ensure Access Control Rules IP Address/CIDR Block as well as Virtual Cloud Networks
    are correct. Repeat for other subscribed regions. From CLI: Execute the following command:

    for region in `oci iam region list | jq -r '.data[] | .name'`; do for compid in `oci iam
    compartment list --compartment-id-in-subtree TRUE 2>/dev/null | jq -r '.data[] | .id'` do
    output=`oci analytics analytics-instance list --compartment-id $compid --region $region
    --all 2>/dev/null | jq -r '.data[] |
    select(."network-endpoint-details"."network-endpoint-type" == "PUBLIC")'` if [ ! -z
    "$output" ]; then echo $output; fi done done Ensure network-endpoint-type are correct.
  CHECK

  desc 'fix', <<~FIX
    From Console: Follow the audit procedure above. For each OAC instance in the returned

    results, click the OAC Instance name Click Edit next to Access Control Rules Click
    +Another Rule and add rules as required From CLI: Follow the audit procedure. Get the json
    input format by executing the below command: oci analytics analytics-instance
    change-network-endpoint --generate-full-command-json-input For each of the OAC Instances
    identified get its details. Update the Access Control Rules , copy the
    network-endpoint-details element from the JSON returned by the above get call, edit it
    appropriately and use it in the following command: oci integration analytics-instance
    change-network-endpoint --from-json '<network endpoints JSON>'
  FIX

  desc 'potential_impacts', <<~POTENTIAL_IMPACTS
    When updating ingress filters for an existing environment, care should be taken to ensure
    that IP addresses and VCNs currently used by administrators, users, and services to access
    your OAC instances are included in the updated filters. Also, these changes will
    temporarily bring the OAC instance offline.
  POTENTIAL_IMPACTS

  impact 0.5

  tag check_id: 'C-2_7'
  tag severity: 'medium'
  tag gid: 'CIS-2_7'
  tag rid: 'xccdf_cis_cis_rule_2_7'
  tag stig_id: '2.7'
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

  allowed_network_endpoint_types = input('allowed_network_endpoint_types')
  allowed_network_endpoint_types = allowed_network_endpoint_types.map { |value| value.to_s.strip.downcase }.reject(&:empty?)

  regions_response = json(command: 'oci iam region-subscription list --all')
  regions_data = regions_response.params.fetch('data', [])
  regions = regions_data.map { |region| region['region-name'] }.compact

  compartments_response = json(command: 'oci iam compartment list --include-root --compartment-id-in-subtree TRUE 2>/dev/null')
  compartments_data = compartments_response.params.fetch('data', [])
  compartment_ids = compartments_data.map { |compartment| compartment['id'] }.compact

  endpoint_type_findings = []
  total_oac_instances = 0

  regions.each do |region|
    compartment_ids.each do |compartment_id|
      instances_response = json(
        command: %(oci analytics analytics-instance list --compartment-id "#{compartment_id}" --region "#{region}" --all 2>/dev/null)
      )
      instances = instances_response.params.fetch('data', [])

      instances.each do |instance|
        next unless instance['lifecycle-state'] == 'ACTIVE'

        total_oac_instances += 1
        endpoint_type = instance.dig('network-endpoint-details', 'network-endpoint-type')
        endpoint_type_normalized = endpoint_type.to_s.strip.downcase
        puts endpoint_type_normalized

        next if allowed_network_endpoint_types.include?(endpoint_type_normalized)

        endpoint_type_findings << {
          'name' => instance['name'],
          'id' => instance['id'],
          'region' => region,
          'compartment_id' => compartment_id,
          'network_endpoint_type' => endpoint_type
        }
      end
    end
  end

  if total_oac_instances.zero?
    impact 0.0
    describe 'Ensure Oracle Analytics Cloud (OAC) access is restricted to allowed sources or deployed within a Virtual Cloud Network.' do
      skip 'No Oracle Analytics Cloud instances found in tenancy.'
    end
  else
    describe 'Ensure Oracle Analytics Cloud (OAC) access is restricted to allowed sources or deployed within a Virtual Cloud Network.' do
      subject { endpoint_type_findings }
      it { should cmp [] }
    end
  end
end
