control '3_3' do
  title 'Ensure In-transit Encryption is enabled on Compute Instance'

  desc <<~DESC
    The Block Volume service provides the option to enable in-transit encryption for
    paravirtualized volume attachments on virtual machine (VM) instances. All the data moving
    between the instance and the block volume is transferred over an internal and highly
    secure network. If you have specific compliance requirements related to the encryption of
    the data while it is moving between the instance and the block volume, you should enable
    the in-transit encryption option.
  DESC

  desc 'check', <<~CHECK
    From Console: Go to https://cloud.oracle.com/compute/instances Select compute instance in

    your compartment. Click on each instance name. Click on Boot volume on the bottom left.
    Under the In-transit encryption column make sure it is Enabled From CLI: Execute the
    following: for region in `oci iam region-subscription list | jq -r '.data[] |
    ."region-name"'`; do for compid in `oci iam compartment list --compartment-id-in-subtree
    TRUE 2>/dev/null | jq -r '.data[] | .id'` do output=`oci compute instance list
    --compartment-id $compid --region $region --all 2>/dev/null | jq -r '.data[] |
    select(."launch-options"."is-pv-encryption-in-transit-enabled" == false )'` if [ ! -z
    "$output" ]; then echo $output; fi done done Ensure no results are returned
  CHECK

  desc 'fix', <<~FIX
    From Console: Navigate to https://cloud.oracle.com/compute/instances Select the instance

    from the Audit Procedure Click Terminate . Determine whether or not to permanently delete
    instance's attached boot volume. Click Terminate instance . Click on Create Instance .
    Fill in the details as per requirements. In the Boot volume section ensure Use in-transit
    encryption is checked. Fill in the rest of the details as per requirements. Click Create .
  FIX

  desc 'potential_impacts', <<~POTENTIAL_IMPACTS
    In-transit encryption for boot and block volumes is only available for virtual machine
    (VM) instances launched from platform images, along with bare metal instances that use the
    following shapes: BM.Standard.E3.128, BM.Standard.E4.128, BM.DenseIO.E4.128. It is not
    supported on other bare metal instances.
  POTENTIAL_IMPACTS

  impact 0.5

  tag check_id: 'C-3_3'
  tag severity: 'medium'
  tag gid: 'CIS-3_3'
  tag rid: 'xccdf_cis_cis_rule_3_3'
  tag stig_id: '3.3'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag 'documentable'

  tag cci: [
    'CCI-002418',
    'CCI-002310',
    'CCI-000183',
    'CCI-000364',
    'CCI-000365',
    'CCI-000366',
    'CCI-000421'
  ]

  tag nist: [
    'SC-8',
    'AC-17 a',
    'IA-5 g',
    'CM-6 a',
    'CM-6 a',
    'CM-6 b',
    'CM-9 a'
  ]

  cmd = <<~CMD
    (
      for region in `oci iam region-subscription list | jq -r '.data[] | ."region-name"'`;
      do
        for compid in `oci iam compartment list --include-root --compartment-id-in-subtree TRUE 2>/dev/null | jq -r '.data[] | .id'`
        do
          output=`oci compute instance list --compartment-id $compid --region $region --all 2>/dev/null | jq -r '.data[] | select(."launch-options"."is-pv-encryption-in-transit-enabled" == false )'`
          if [ ! -z "$output" ]; then echo $output; fi
        done
      done
    ) | jq -nR '[inputs]'
  CMD

  json_output = json(command: cmd)
  output = json_output.params

  describe 'Ensure In-transit Encryption is enabled on Compute Instance' do
    subject { output }
    it { should be_empty }
  end
end
