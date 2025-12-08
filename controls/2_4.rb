control '2_4' do
  title 'Ensure no network security groups allow ingress from 0.0.0.0/0 to port 3389'

  desc <<~DESC
    Network security groups provide stateful filtering of ingress/egress network traffic to
    OCI resources. It is recommended that no security group allows unrestricted ingress access
    to port 3389. Removing unfettered connectivity to remote console services, such as Remote
    Desktop Protocol (RDP), reduces a server's exposure to risk.
  DESC

  desc 'check', <<~CHECK
    From CLI: Issue the following command, it should not return anything. for region in $(oci

    iam region-subscription list | jq -r '.data[] | ."region-name"') do echo "Enumerating
    region $region" for compid in $(oci iam compartment list --include-root
    --compartment-id-in-subtree TRUE 2>/dev/null | jq -r '.data[] | .id') do echo "Enumerating
    compartment $compid" for nsgid in $(oci network nsg list --compartment-id $compid --region
    $region --all 2>/dev/null | jq -r '.data[] | .id') do output=$(oci network nsg rules list
    --nsg-id=$nsgid --all 2>/dev/null | jq -r '.data[] | select(.source == "0.0.0.0/0" and
    .direction == "INGRESS" and ((."tcp-options"."destination-port-range".max >= 3389 and
    ."tcp-options"."destination-port-range".min <= 3389) or
    ."tcp-options"."destination-port-range" == null))') if [ ! -z "$output" ]; then echo
    "NSGID: ", $nsgid, "Security Rules: ", $output; fi done done done From Cloud Guard: To
    Enable Cloud Guard Auditing: Ensure Cloud Guard is enabled in the root compartment of the
    tenancy. For more information about enabling Cloud Guard, please look at the instructions
    included in Recommendation 3.15. From Console: Type Cloud Guard into the Search box at the
    top of the Console. Click Cloud Guard from the “Services” submenu. Click Detector Recipes
    in the Cloud Guard menu. Click OCI Configuration Detector Recipe (Oracle Managed) under
    the Recipe Name column. Find NSG ingress rule contains disallowed IP/port in the Detector
    Rules column. Select the vertical ellipsis icon and chose Edit on the NSG ingress rule
    contains disallowed IP/port row. In the Edit Detector Rule window find the Input Setting
    box and verify/add to the Restricted Protocol: Ports List setting to TCP:[3389],
    UDP:[3389]. Click the Save button. From CLI: Update the NSG ingress rule contains
    disallowed IP/port Detector Rule in Cloud Guard to generate Problems if a network security
    group allows ingress network traffic to port 3389 with the following command: oci
    cloud-guard detector-recipe-detector-rule update --detector-recipe-id <insert detector
    recipe ocid> --detector-rule-id VCN_NSG_INGRESS_RULE_PORTS_CHECK --details
    '{"configurations":[ {"configKey" : "nsgIngressRuleDisallowedPortsConfig", "name" :

    "Default disallowed ports", "value" : "TCP:[3389], UDP:[3389]", "dataType" : null,
    "values" : null }]}'
  CHECK

  desc 'fix', <<~FIX
    From CLI: Using the details returned from the audit procedure either: Remove the security

    rules oci network nsg rules remove --nsg-id=<NSGID from audit output> or Update the
    security rules oci network nsg rules update --nsg-id=<NSGID from audit output>
    --security-rules=<updated security-rules JSON (without the isValid or TimeCreated fields)>
    eg: oci network nsg rules update
    --nsg-id=ocid1.networksecuritygroup.oc1.iad.xxxxxxxxxxxxxxxxxxxxxx --security-rules='[{
    "description": null, "destination": null, "destination-type": null, "direction":

    "INGRESS", "icmp-options": null, "id": "709001", "is-stateless": null, "protocol": "6",
    "source": "140.238.154.0/24", "source-type": "CIDR_BLOCK", "tcp-options": {
    "destination-port-range": { "max": 3389, "min": 3389 }, "source-port-range": null },
    "udp-options": null }]'
  FIX

  desc 'potential_impacts', <<~POTENTIAL_IMPACTS
    For updating an existing environment, care should be taken to ensure that administrators
    currently relying on an existing ingress from 0.0.0.0/0 have access to ports 22 and/or
    3389 through another network security group or security list.
  POTENTIAL_IMPACTS

  impact 0.5

  tag check_id: 'C-2_4'
  tag severity: 'medium'
  tag gid: 'CIS-2_4'
  tag rid: 'xccdf_cis_cis_rule_2_4'
  tag stig_id: '2.4'
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

    cmd = <<~CMD
    (
      for region in $(oci iam region-subscription list | jq -r '.data[] |."region-name"')
      do
        for compid in $(oci iam compartment list --include-root --compartment-id-in-subtree TRUE 2>/dev/null | jq -r '.data[] | .id')
        do
          for nsgid in $(oci network nsg list --compartment-id $compid --region $region --all 2>/dev/null | jq -r '.data[] | .id')
          do
            output=$(oci network nsg rules list --nsg-id=$nsgid --all2>/dev/null | jq -r '.data[] | select(.source == "0.0.0.0/0" and .direction== "INGRESS" and ((."tcp-options"."destination-port-range".max >= 3389 and."tcp-options"."destination-port-range".min <= 3389) or ."tcp-options"."destination-port-range" == null))')
            if [ ! -z "$output" ]; then echo "NSGID: ", $nsgid, "SecurityRules: ", $output; fi
          done
        done
      done
    ) | jq -nR '[inputs]'
  CMD

  json_output = json(command: cmd)
  output = json_output.params

  describe 'Ensure no network security groups allow ingress from 0.0.0.0/0 to port 3389' do
    subject { output }
    it { should be_empty }
  end
end
