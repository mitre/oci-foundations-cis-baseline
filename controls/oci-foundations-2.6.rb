control 'oci-foundations-2.6' do
  title 'Ensure Oracle Integration Cloud (OIC) access is restricted to allowed sources.'

  desc <<~DESC
    Oracle Integration (OIC) is a complete, secure, but lightweight integration solution that
    enables you to connect your applications in the cloud. It simplifies connectivity between
    your applications and connects both your applications that live in the cloud and your
    applications that still live on premises. Oracle Integration provides secure,
    enterprise-grade connectivity regardless of the applications you are connecting or where
    they reside. OIC instances are created within an Oracle managed secure private network
    with each having a public endpoint. The capability to configure ingress filtering of
    network traffic to protect your OIC instances from unauthorized network access is
    included. It is recommended that network access to your OIC instances be restricted to
    your approved corporate IP Addresses or Virtual Cloud Networks (VCN)s. Restricting
    connectivity to OIC Instances reduces an OIC instance’s exposure to risk.
  DESC

  desc 'check', <<~CHECK
    From Console: Login into the OCI Console Click in the search bar, top of the screen. Type

    Advanced Resource Query and hit enter. Click the Advanced Resource Query button in the
    upper right of the screen. Enter the following query in the query box: query
    integrationinstance resources For each OIC Instance returned click on the link under
    Display name Click on Network Access 8 .Ensure Restrict Network Access is selected and the
    IP Address/CIDR Block as well as Virtual Cloud Networks are correct Repeat for other
    subscribed regions From CLI: Execute the following command: for region in `oci iam region
    list | jq -r '.data[] | .name'`; do for compid in `oci iam compartment list
    --compartment-id-in-subtree TRUE 2>/dev/null | jq -r '.data[] | .id'` do output=`oci
    integration integration-instance list --compartment-id $compid --region $region --all
    2>/dev/null | jq -r '.data[] | select(."network-endpoint-details"."network-endpoint-type"
    == null)'` if [ ! -z "$output" ]; then echo $output; fi done done Ensure
    allowlisted-http-ips and allowed-http-vcns are correct
  CHECK

  desc 'fix', <<~FIX
    From Console: Follow the audit procedure above. For each OIC instance in the returned

    results, click the OIC Instance name Click Network Access Either edit the Network Access
    to be more restrictive From CLI Follow the audit procedure. Get the json input format
    using the below command: oci integration integration-instance change-network-endpoint
    --generate-param-json-input 3.For each of the OIC Instances identified get its details.
    4.Update the Network Access , copy the network-endpoint-details element from the JSON
    returned by the above get call, edit it appropriately and use it in the following command
    Oci integration integration-instance change-network-endpoint --id <oic-instance-id>
    --from-json '<network endpoints JSON>'
  FIX

  desc 'potential_impacts', <<~POTENTIAL_IMPACTS
    When updating ingress filters for an existing environment, care should be taken to ensure
    that IP addresses and VCNs currently used by administrators, users, and services to access
    your OIC instances are included in the updated filters.
  POTENTIAL_IMPACTS

  impact 0.5

  tag severity: 'medium'
  tag benchmark_ref: '2.6'
  tag cis_level: 'Level 1'
  tag assessment_status: 'Manual'
  tag cis_controls: %w[4.4 12.3]

  tag cci: %w[CCI-001097 CCI-001184]

  tag nist: ['SC-7', 'SC-23']

  allowed_oic_allowlisted_http_ips = input('allowed_oic_allowlisted_http_ips')
  allowed_oic_allowlisted_http_ips = allowed_oic_allowlisted_http_ips.map { |value| value.to_s.strip.downcase }.reject(&:empty?).uniq

  allowed_oic_allowlisted_http_vcns = input('allowed_oic_allowlisted_http_vcns')
  allowed_oic_allowlisted_http_vcns = {} unless allowed_oic_allowlisted_http_vcns.is_a?(Hash)
  expected_vcn_ip_pairs = allowed_oic_allowlisted_http_vcns.flat_map do |vcn_id, ips|
    normalized_vcn_id = vcn_id.to_s.strip.downcase
    next [] if normalized_vcn_id.empty?

    Array(ips).map do |ip|
      normalized_ip = ip.to_s.strip.downcase
      next if normalized_ip.empty?

      { 'vcn_id' => normalized_vcn_id, 'ip' => normalized_ip }
    end
  end.compact.uniq

  regions_response = json(command: 'oci iam region-subscription list --all')
  regions_data = regions_response.params.fetch('data', [])
  regions = regions_data.map { |region| region['region-name'] }.compact

  compartments_response = json(command: 'oci iam compartment list --include-root --compartment-id-in-subtree TRUE 2>/dev/null')
  compartments_data = compartments_response.params.fetch('data', [])
  compartment_ids = compartments_data.map { |compartment| compartment['id'] }.compact

  oic_access_findings = []
  total_oic_instances = 0

  regions.each do |region|
    compartment_ids.each do |compartment_id|
      instances_response = json(command: %(oci integration integration-instance list --compartment-id "#{compartment_id}" --region "#{region}" --all 2>/dev/null))
      instances = instances_response.params.fetch('data', [])

      instances.each do |instance|
        next unless instance['lifecycle-state'] == 'ACTIVE'

        total_oic_instances += 1
        endpoint_details = instance.fetch('network-endpoint-details', {}) || {}
        allowlisted_ips = Array(endpoint_details['allowlisted-http-ips']).map { |ip| ip.to_s.strip.downcase }.reject(&:empty?).uniq
        allowlisted_vcns = Array(endpoint_details['allowlisted-http-vcns'])
        actual_vcn_ip_pairs = allowlisted_vcns.flat_map do |allowlisted_vcn|
          next [] unless allowlisted_vcn.is_a?(Hash)

          normalized_vcn_id = allowlisted_vcn['id'].to_s.strip.downcase
          next [] if normalized_vcn_id.empty?

          Array(allowlisted_vcn['allowlisted-ips']).map do |ip|
            normalized_ip = ip.to_s.strip.downcase
            next if normalized_ip.empty?

            { 'vcn_id' => normalized_vcn_id, 'ip' => normalized_ip }
          end
        end.compact.uniq

        unexpected_ips = allowlisted_ips - allowed_oic_allowlisted_http_ips
        missing_ips = allowed_oic_allowlisted_http_ips - allowlisted_ips
        unexpected_vcn_pairs = actual_vcn_ip_pairs - expected_vcn_ip_pairs
        missing_vcn_pairs = expected_vcn_ip_pairs - actual_vcn_ip_pairs

        next if unexpected_ips.empty? && missing_ips.empty? && unexpected_vcn_pairs.empty? && missing_vcn_pairs.empty?

        oic_access_findings << <<~ENTRY.chomp
          Name: #{instance['display-name']}
          ID: #{instance['id']}
          Region: #{region}
          Compartment ID: #{compartment_id}
          Missing IPs: #{missing_ips.empty? ? 'None' : missing_ips.join(', ')}
          Unexpected IPs: #{unexpected_ips.empty? ? 'None' : unexpected_ips.join(', ')}
          Missing VCN/IP Pairs: #{missing_vcn_pairs.empty? ? 'None' : missing_vcn_pairs.map { |pair| "#{pair['vcn_id']}:#{pair['ip']}" }.join(', ')}
          Unexpected VCN/IP Pairs: #{unexpected_vcn_pairs.empty? ? 'None' : unexpected_vcn_pairs.map { |pair| "#{pair['vcn_id']}:#{pair['ip']}" }.join(', ')}
        ENTRY
      end
    end
  end

  if total_oic_instances.zero?
    impact 0.0
    describe 'Ensure Oracle Integration Cloud (OIC) access is restricted to allowed sources' do
      skip 'No Oracle Integration Cloud instances found in tenancy.'
    end
  else
    numbered_findings = oic_access_findings.each_with_index.map do |entry, index|
      "[#{index + 1}]\n#{entry}"
    end

    describe 'Oracle Integration Cloud instances' do
      it 'should allow access only from approved IPs and VCN/IP pairs' do
        expect(oic_access_findings).to be_empty, <<~MSG
          Non-compliant findings:

          #{numbered_findings.join("\n\n")}
        MSG
      end
    end
  end
end
