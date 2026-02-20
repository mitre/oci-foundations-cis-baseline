control 'oci-foundations-4.1' do
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
    "data[?'lifecycle-state'=='ACTIVE'].{name:"tag-definition-name",value:value}"
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

  tag severity: 'medium'
  tag benchmark_ref: '4.1'
  tag cis_level: 'Level 1'
  tag assessment_status: 'Automated'
  tag cis_controls: %w[1.1]

  tag cci: %w[CCI-000389]

  tag nist: ['CM-8']

  tenancy_ocid = input('tenancy_ocid')

  cmd = "oci iam tag-default list --compartment-id='#{tenancy_ocid}' --query=\"data[?\\\"lifecycle-state\\\"=='ACTIVE'].{\\\"name\\\":\\\"tag-definition-name\\\",\\\"value\\\":value}\""

  json_output = json(command: cmd)
  output = json_output.params

  values = output.map { |dict| dict['value'] }

  describe 'Ensure default tags are used on resources' do
    subject { values }
    it { should include '${iam.principal.name}' }
  end
end
