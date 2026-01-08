control '2_5' do
  title 'Ensure the default security list of every VCN restricts all traffic except ICMP within VCN'

  desc <<~DESC
    A default security list is created when a Virtual Cloud Network (VCN) is created and
    attached to the public subnets in the VCN. Security lists provide stateful or stateless
    filtering of ingress and egress network traffic to OCI resources in the VCN. It is
    recommended that the default security list does not allow unrestricted ingress and egress
    access to resources in the VCN. Removing unfettered connectivity to OCI resource, reduces
    a server's exposure to unauthorized access or data exfiltration.
  DESC

  desc 'check', <<~CHECK
    From Console: Login into the OCI Console Click on Networking -> Virtual Cloud Networks

    from the services menu For each VCN listed Click on Security Lists Click on Default
    Security List for <VCN Name> Verify that there is no Ingress rule with 'Source 0.0.0.0/0'
    Verify that there is no Egress rule with 'Destination 0.0.0.0/0, All Protocols'
  CHECK

  desc 'fix', <<~FIX
    From Console: Login into the OCI Console Click on Networking -> Virtual Cloud Networks

    from the services menu For each VCN listed Click on Security Lists Click on Default
    Security List for <VCN Name> Identify the Ingress Rule with 'Source 0.0.0.0/0' Either Edit
    the Security rule to restrict the source and/or port range or delete the rule. Identify
    the Egress Rule with 'Destination 0.0.0.0/0, All Protocols' Either Edit the Security rule
    to restrict the source and/or port range or delete the rule.
  FIX

  desc 'potential_impacts', <<~POTENTIAL_IMPACTS
    For updating an existing environment, care should be taken to ensure that administrators
    currently relying on an existing ingress from 0.0.0.0/0 have access to port 22 through
    another network security group and servers have egress to specified ports and protocols
    through another network security group.
  POTENTIAL_IMPACTS

  impact 0.5

  tag check_id: 'C-2_5'
  tag severity: 'medium'
  tag gid: 'CIS-2_5'
  tag rid: 'xccdf_cis_cis_rule_2_5'
  tag stig_id: '2.5'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag 'documentable'

  tag cci: [
    'CCI-002668',
    'CCI-002669',
    'CCI-001243',
    'CCI-001184',
    'CCI-000364',
    'CCI-000366',
    'CCI-000381'
  ]

  tag nist: [
    'SI-4 (11)',
    'SI-4 (13) (c)',
    'SI-3 c 2',
    'SC-23',
    'CM-6 a',
    'CM-6 b',
    'CM-7 a'
  ]

  regions_response = json(command: 'oci iam region-subscription list --all')
  regions_data = regions_response.params.fetch('data', [])
  regions = regions_data.map { |region| region['region-name'] }.compact

  compartments_response = json(command: 'oci iam compartment list --include-root --compartment-id-in-subtree TRUE 2>/dev/null')
  compartments_data = compartments_response.params.fetch('data', [])
  compartments = compartments_data.map { |compartment| compartment['id'] }.compact

  security_list_findings = []

  regions.each do |region|
    compartments.each do |compartment_id|
      vcns_response = json(
        command: %(oci network vcn list --compartment-id "#{compartment_id}" --region "#{region}" --all 2>/dev/null)
      )
      vcns = vcns_response.params.fetch('data', [])

      vcns.each do |vcn|
        security_list_id = vcn['default-security-list-id']
        next if security_list_id.to_s.strip.empty?

        security_list_check_cmd = %(
          oci network security-list get --security-list-id "#{security_list_id}" --region "#{region}" |
          jq '{ bad_ingress: [.data["ingress-security-rules"][]? | select(.source=="0.0.0.0/0")],
                bad_egress:  [.data["egress-security-rules"][]? | select(.destination=="0.0.0.0/0" and (.protocol|ascii_downcase)=="all")] }'
        )
        security_list_check = json(command: security_list_check_cmd).params
        bad_ingress = security_list_check['bad_ingress'] || []
        bad_egress = security_list_check['bad_egress'] || []

        next if bad_ingress.empty? && bad_egress.empty?

        security_list_findings << {
          'vcn_name' => vcn['display-name'],
          'region' => region
        }
      end
    end
  end

  describe 'Ensure the default security list of every VCN restricts all traffic except ICMP within VCN' do
    subject { security_list_findings }
    it { should be_empty }
  end
end
