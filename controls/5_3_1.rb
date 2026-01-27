control '5_3_1' do
  title 'Ensure File Storage Systems are encrypted with Customer Managed Keys (CMK)'

  desc <<~DESC
    Oracle Cloud Infrastructure File Storage service (FSS) provides a durable, scalable,
    secure, enterprise-grade network file system. By default, the Oracle service manages the
    keys that encrypt FSS file systems. FSS file systems can also be encrypted using a
    customer managed key. Encryption of FSS systems provides an additional level of security
    for your data. Management of encryption keys is critical to protecting and accessing
    protected data. Customers should identify FSS file systems that are encrypted with Oracle
    service managed keys in order to determine if they want to manage the keys for certain FSS
    file systems and then apply their own key lifecycle management to the selected FSS file
    systems.
  DESC

  desc 'check', <<~CHECK
    From Console: Login into the OCI Console Click in the search bar, top of the screen. Type

    Advanced Resource Query and click enter. Click the Advanced Resource Query button in the
    upper right of the screen. Enter the following query in the query box: query filesystem
    resources For each file storage system returned click on the link under Display name
    Ensure Encryption Key does not say Oracle-managed key Repeat for other subscribed regions

    From CLI: Execute the following command: for region in `oci iam region list | jq -r

    '.data[] | .name'`; do for fssid in `oci search resource structured-search --region
    $region --query-text "query filesystem resources" 2>/dev/null | jq -r '.data.items[] |
    .identifier'` do output=`oci fs file-system get --file-system-id $fssid --region $region
    2>/dev/null | jq -r '.data | select(."kms-key-id" == "").id'` if [ ! -z "$output" ]; then
    echo $output; fi done done Ensure query returns no results
  CHECK

  desc 'fix', <<~FIX
    From Console: Follow the audit procedure above. For each File Storage System in the

    returned results, click the File System Storage Click Edit next to Encryption Key Select
    Encrypt using customer-managed keys Select the Vault Compartment and Vault Select the
    Master Encryption Key Compartment and Master Encryption key Click Save Changes From CLI:

    Follow the audit procedure. For each File Storage System identified get its OCID. Execute
    the following command: oci bv volume-kms-key update –volume-id <volume OCID> --kms-key-id
    <kms key OCID>
  FIX

  desc 'potential_impacts', <<~POTENTIAL_IMPACTS
    [object Object]
  POTENTIAL_IMPACTS

  impact 0.5

  tag check_id: 'C-5_3_1'
  tag severity: 'medium'
  tag gid: 'CIS-5_3_1'
  tag rid: 'xccdf_cis_cis_rule_5_3_1'
  tag stig_id: '5.3.1'
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

  cmd = <<~CMD
    (
      for region in `oci iam region-subscription list | jq -r '.data[] | ."region-name"'`;
      do
        for fssid in `oci search resource structured-search --region $region --query-text "query filesystem resources" 2>/dev/null | jq -r '.data.items[] |.identifier'`
        do
          output=`oci fs file-system get --file-system-id $fssid --region $region 2>/dev/null | jq -r '.data | select(."kms-key-id" == "").id'`
          if [ ! -z "$output" ]; then echo $output; fi
        done
      done
    ) | jq -nR '[inputs]'
  CMD

  json_output = json(command: cmd)
  output = json_output.params

  describe 'Ensure File Storage Systems are encrypted with Customer Managed Keys (CMK)' do
    subject { output }
    it { should be_empty }
  end
end
