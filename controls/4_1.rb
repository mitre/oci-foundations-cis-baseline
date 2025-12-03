control '4_1' do
  title 'Ensure default tags are used on resources'

  desc <<~DESC
    Default tags automatically apply a set of tags to supported resources in a compartment.
    Enforcing a tag that captures the principal who created the resource improves traceability
    and ownership for audit and lifecycle management.
  DESC

  desc 'check', <<~CHECK
    From CLI: Execute the following command and ensure at least one active tag default value
    is set to ${iam.principal.name}:

    oci iam tag-default list --compartment-id "<tenancy-ocid>" --all --query
    "data[?'lifecycle-state'=='ACTIVE'].{name:\"tag-definition-name\",value:value}"
  CHECK

  desc 'fix', <<~FIX
    From Console: Login to OCI Console. From the navigation menu, select Identity &
    Security. Under Identity, select Compartments and choose the root compartment. Under
    Resources, select Tag Defaults. Create or edit a tag default so that a tag value is set to
    ${iam.principal.name}.

    From CLI: Create or update the relevant tag default using oci iam tag-default
    create/update with the value ${iam.principal.name}.
  FIX

  desc 'potential_impacts', <<~POTENTIAL_IMPACTS
    Applying tag defaults adds tags to every new supported resource in the compartment; verify
    the key and value so that unintended tags are not propagated.
  POTENTIAL_IMPACTS

  impact 0.5

  tag check_id: 'C-4_1'
  tag severity: 'medium'
  tag gid: 'CIS-4_1'
  tag rid: 'xccdf_cis_cis_rule_4_1'
  tag stig_id: '4.1'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag 'documentable'

  tag cci: [
    'CCI-000389',
    'CCI-000395',
    'CCI-000399',
    'CCI-001780',
    'CCI-000389',
    'CCI-000395',
    'CCI-001780'
  ]

  tag nist: [
    'CM-8 a 1',
    'CM-8 a 3',
    'CM-8 a 4',
    'CM-8 b',
    'CM-8 a 1',
    'CM-8 a 3',
    'CM-8 b'
  ]

  tenancy_ocid = input('tenancy_ocid')
  
  cmd = "oci iam tag-default list --compartment-id='" + tenancy_ocid + "' --query=\"data[?\\\"lifecycle-state\\\"=='ACTIVE'].{\\\"name\\\":\\\"tag-definition-name\\\",\\\"value\\\":value}\""

  json_output = json(command: cmd)
  output = json_output.params

  values = output.map { |dict| dict['value'] }

  describe 'Ensure default tags are used on resources' do
    subject { values }
    it { should include '${iam.principal.name}' }
  end
end
