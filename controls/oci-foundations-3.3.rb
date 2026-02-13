control 'oci-foundations-3.3' do
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

  tag severity: 'medium'
  tag benchmark_ref: '3.3'
  tag cis_level: 'Level 1'
  tag assessment_status: 'Automated'
  tag cis_controls: %w[3.10 4.1]

  tag cci: %w[CCI-002418 CCI-000364]

  tag nist: ['SC-8', 'CM-6']

  regions_response = json(command: 'oci iam region-subscription list --all')
  regions_data = regions_response.params.fetch('data', [])
  regions = regions_data.map { |region| region['region-name'] }.compact

  compartments_response = json(command: 'oci iam compartment list --include-root --compartment-id-in-subtree TRUE --all 2>/dev/null')
  compartments_data = compartments_response.params.fetch('data', [])
  compartment_ids = compartments_data.map { |compartment| compartment['id'] }.compact

  non_compliant_instances = []
  total_instances = 0

  regions.each do |region|
    compartment_ids.each do |compartment_id|
      instances_response = json(command: %(oci compute instance list --compartment-id "#{compartment_id}" --region "#{region}" --all 2>/dev/null))
      instances = instances_response.params.fetch('data', [])

      instances.each do |instance|
        total_instances += 1
        launch_options = instance['launch-options']
        in_transit_enabled = launch_options && launch_options['is-pv-encryption-in-transit-enabled']

        next unless in_transit_enabled == false

        non_compliant_instances << <<~ENTRY.chomp
          Display Name: #{instance['display-name']}
          ID: #{instance['id']}
          Region: #{region}
          Compartment ID: #{compartment_id}
          Launch Options Present: #{!launch_options.nil?}
          PV Encryption In Transit Enabled: #{in_transit_enabled}
        ENTRY
      end
    end
  end

  if total_instances.zero?
    impact 0.0
    describe 'Ensure In-transit Encryption is enabled on Compute Instance' do
      skip 'No compute instances found in tenancy.'
    end
  else
    numbered_findings = non_compliant_instances.each_with_index.map do |entry, index|
      "[#{index + 1}]\n#{entry}"
    end

    describe 'Compute instances' do
      it 'should have in-transit encryption enabled' do
        expect(non_compliant_instances).to be_empty, <<~MSG
          Non-compliant findings:

          #{numbered_findings.join("\n\n")}
        MSG
      end
    end
  end
end
