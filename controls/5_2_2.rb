control '5_2_2' do
  title 'Ensure boot volumes are encrypted with Customer Managed Key (CMK).'

  desc <<~DESC
    When you launch a virtual machine (VM) or bare metal instance based on a platform image or
    custom image, a new boot volume for the instance is created in the same compartment. That
    boot volume is associated with that instance until you terminate the instance. By default,
    the Oracle service manages the keys that encrypt this boot volume. Boot Volumes can also
    be encrypted using a customer managed key. Encryption of boot volumes provides an
    additional level of security for your data. Management of encryption keys is critical to
    protecting and accessing protected data. Customers should identify boot volumes encrypted
    with Oracle service managed keys in order to determine if they want to manage the keys for
    certain boot volumes and then apply their own key lifecycle management to the selected
    boot volumes.
  DESC

  desc 'check', <<~CHECK
    From Console: Login into the OCI Console Click in the search bar, top of the screen. Type

    Advanced Resource Query and click enter. Click the Advanced Resource Query button in the
    upper right of the screen. Enter the following query in the query box: query bootvolume
    resources For each boot volume returned click on the link under Display name Ensure
    Encryption Key does not say Oracle managed key Repeat for other subscribed regions From
    CLI: Execute the following command: for region in `oci iam region list | jq -r '.data[] |
    .name'`; do for bvid in `oci search resource structured-search --region $region
    --query-text "query bootvolume resources" 2>/dev/null | jq -r '.data.items[] |
    .identifier'` do output=`oci bv boot-volume get --boot-volume-id $bvid 2>/dev/null | jq -r
    '.data | select(."kms-key-id" == null).id'` if [ ! -z "$output" ]; then echo $output; fi
    done done Ensure query returns no results.
  CHECK

  desc 'fix', <<~FIX
    From Console: Follow the audit procedure above. For each Boot Volume in the returned

    results, click the Boot Volume name Click Assign next to Encryption Key Select the Vault
    Compartment and Vault Select the Master Encryption Key Compartment and Master Encryption
    key Click Assign From CLI: Follow the audit procedure. For each boot volume identified get
    its OCID. Execute the following command: oci bv boot-volume-kms-key update
    --boot-volume-id <Boot Volume OCID> --kms-key-id <KMS Key OCID>
  FIX

  desc 'potential_impacts', <<~POTENTIAL_IMPACTS
    [object Object]
  POTENTIAL_IMPACTS

  impact 0.5

  tag check_id: 'C-5_2_2'
  tag severity: 'medium'
  tag gid: 'CIS-5_2_2'
  tag rid: 'xccdf_cis_cis_rule_5_2_2'
  tag stig_id: '5.2.2'
  tag gtitle: '<GroupDescription></GroupDescription>'

  tag cci: [
    'CCI-001199',
    'CCI-002472',
    'CCI-000183',
    'CCI-000051',
    'CCI-002856',
    'CCI-003205'
  ]

  tag nist: [
    'SC-28',
    'SC-28',
    'IA-5 g',
    'AC-8 a',
    'CP-12',
    'SA-12 (8)'
  ]
end
