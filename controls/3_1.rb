control '3_1' do
  title 'Ensure Compute Instance Legacy Metadata service endpoint is disabled'

  desc <<~DESC
    Compute Instances that utilize Legacy MetaData service endpoints (IMDSv1) are susceptible
    to potential SSRF attacks. To bolster security measures, it is strongly advised to
    reconfigure Compute Instances to adopt Instance Metadata Service v2, aligning with the
    industry's best security practices. Enabling Instance Metadata Service v2 enhances
    security and grants precise control over metadata access. Transitioning from IMDSv1
    reduces the risk of SSRF attacks, bolstering system protection. IMDv1 poses security risks
    due to its inferior security measures and limited auditing capabilities. Transitioning to
    IMDv2 ensures a more secure environment with robust security features and improved
    monitoring capabilities.
  DESC

  desc 'check', <<~CHECK
    From Console: Login to the OCI Console Select compute instance in your compartment. Click

    on each instance name. In the Instance Details section, next to Instance metadata service
    make sure Version 2 only is selected. From CLI: Run command: for region in `oci iam
    region-subscription list | jq -r '.data[] | ."region-name"'`; do for compid in `oci iam
    compartment list --compartment-id-in-subtree TRUE 2>/dev/null | jq -r '.data[] | .id'` do
    output=`oci compute instance list --compartment-id $compid --region $region --all
    2>/dev/null | jq -r '.data[] |
    select(."instance-options"."are-legacy-imds-endpoints-disabled" == false )'` if [ ! -z
    "$output" ]; then echo $output; fi done done No results should be returned
  CHECK

  desc 'fix', <<~FIX
    From Console: Login to the OCI Console Click on the search box at the top of the console

    and search for compute instance name. Click on the instance name, In the Instance Details
    section, next to Instance Metadata Service, click Edit . For the Instance metadata service
    , select the Version 2 only option. Click Save Changes . Note : Disabling IMDSv1 on an
    incompatible instance may result in connectivity issues upon launch. To re-enable IMDSv1,
    follow these steps: On the Instance Details page in the Console, click Edit next to
    Instance Metadata Service. Choose the Version 1 and version 2 option, and save your
    changes. From CLI: Run Below Command, oci compute instance update --instance-id
    [instance-ocid] --instance-options '{"areLegacyImdsEndpointsDisabled" :"true"}' This will
    set Instance Metadata Service to use Version 2 Only.
  FIX

  desc 'potential_impacts', <<~POTENTIAL_IMPACTS
    If you disable IMDSv1 on an instance that does not support IMDSv2, you might not be able
    to connect to the instance when you launch it. IMDSv2 is supported on the following
    platform images: Oracle Autonomous Linux 8.x images Oracle Autonomous Linux 7.x images
    released in June 2020 or later Oracle Linux 8.x, Oracle Linux 7.x, and Oracle Linux 6.x
    images released in July 2020 or later Other platform images, most custom images, and most
    Marketplace images do not support IMDSv2. Custom Linux images might support IMDSv2 if
    cloud-init is updated to version 20.3 or later and Oracle Cloud Agent is updated to
    version 0.0.19 or later. Custom Windows images might support IMDSv2 if Oracle Cloud Agent
    is updated to version 1.0.0.0 or later; cloudbase-init does not support IMDSv2.
  POTENTIAL_IMPACTS

  impact 0.5

  tag check_id: 'C-3_1'
  tag severity: 'medium'
  tag gid: 'CIS-3_1'
  tag rid: 'xccdf_cis_cis_rule_3_1'
  tag stig_id: '3.1'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag 'documentable'

  tag cci: [
    'CCI-000381',
    'CCI-000382',
    'CCI-000380'
  ]

  tag nist: [
    'CM-7 a',
    'CM-7 b',
    'CM-7 b'
  ]

  cmd = <<~CMD
    (
      for region in `oci iam region-subscription list | jq -r '.data[] | ."region-name"'`;
      do
        for compid in `oci iam compartment list --include-root --compartment-id-in-subtree TRUE 2>/dev/null | jq -r '.data[] | .id'`
        do
          output=`oci compute instance list --compartment-id $compid --region $region --all 2>/dev/null | jq -r'.data[]|select(."instance-options"."are-legacy-imds-endpoints-disabled" == false )'`
          if [ ! -z "$output" ]; then echo $output; fi
        done
      done
    ) | jq -nR '[inputs]'
  CMD

  json_output = json(command: cmd)
  output = json_output.params

  describe 'Ensure Compute Instance Legacy Metadata service endpoint is disabled' do
    subject { output }
    it { should be_empty }
  end
end
