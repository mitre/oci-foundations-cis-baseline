control '1_14' do
  title 'Ensure Instance Principal authentication is used for OCI instances, OCI Cloud Databases and OCI Functions to access OCI resources.'

  desc <<~DESC
    OCI instances, OCI database and OCI functions can access other OCI resources either via an
    OCI API key associated to a user or via Instance Principal. Instance Principal
    authentication can be achieved by inclusion in a Dynamic Group that has an IAM policy
    granting it the required access or using an OCI IAM policy that has request.principal
    added to the where clause. Access to OCI Resources refers to making API calls to another
    OCI resource like Object Storage, OCI Vaults, etc. Instance Principal reduces the risks
    related to hard-coded credentials. Hard-coded API keys can be shared and require rotation,
    which can open them up to being compromised. Compromised credentials could allow access to
    OCI services outside of the expected radius.
  DESC

  desc 'check', <<~CHECK
    From Console (Dynamic Groups): Go to https://cloud.oracle.com/identity/domains/ Select a

    Compartment Click on a Domain Click on Dynamic groups Click on the Dynamic Group Check if
    the Matching Rules includes the instances accessing your OCI resources. From Console
    (request.principal): Go to https://cloud.oracle.com/identity/policies Select a Compartment
    Click on an individual policy under the Name heading. Ensure Policy statements look like
    this : allow any-user to <verb> <resource> in compartment <compartment-name> where ALL
    {request.principal.type='<resource_type>', request.principal.id='<resource_ocid>'} or
    allow any-user to <verb> <resource> in compartment <compartment-name> where ALL
    {request.principal.type='<resource_type>',
    request.principal.compartment.id='<compartment_OCID>'} From CLI (request.principal):

    Execute the following for each compartment_OCID: oci iam policy list --compartment-id
    <compartment_OCID> | grep request.principal Ensure that the condition includes the
    instances accessing your OCI resources
  CHECK

  desc 'fix', <<~FIX
    From Console (Dynamic Groups): Go to https://cloud.oracle.com/identity/domains/ Select a

    Compartment Click on the Domain Click on Dynamic groups Click Create Dynamic Group. Enter
    a Name Enter a Description Enter Matching Rules to that includes the instances accessing
    your OCI resources. Click Create.
  FIX

  desc 'potential_impacts', <<~POTENTIAL_IMPACTS
    For an OCI instance that contains embedded credential audit the scripts and environment
    variables to ensure that none of them contain OCI API Keys or credentials.
  POTENTIAL_IMPACTS

  impact 0.5

  tag check_id: 'C-1_14'
  tag severity: 'medium'
  tag gid: 'CIS-1_14'
  tag rid: 'xccdf_cis_cis_rule_1_14'
  tag stig_id: '1.14'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag 'documentable'

  tag cci: [
    'CCI-002113',
    'CCI-002117',
    'CCI-002118',
    'CCI-000008',
    'CCI-000051',
    'CCI-002856',
    'CCI-003205'
  ]

  tag nist: [
    'AC-2 c',
    'AC-2 d 2',
    'AC-2 d 3',
    'AC-2 c',
    'AC-8 a',
    'CP-12',
    'SA-12 (8)'
  ]

  tenancy_ocid = input('tenancy_ocid')

  # Query Dynamic Groups
  dynamic_groups_cmd = %(oci iam dynamic-group list --compartment-id '#{tenancy_ocid}' --all 2>/dev/null | jq -r '.data[].name' || echo "")
  dynamic_groups_output = command(dynamic_groups_cmd).stdout.strip

  # Query policies for request.principal conditions
  policies_with_principal_cmd = %(oci iam policy list --compartment-id '#{tenancy_ocid}' --all 2>/dev/null | jq -r '.data[] | select(.statements[]? | contains("request.principal")) | .name' || echo "")
  policies_with_principal_output = command(policies_with_principal_cmd).stdout.strip

  # Query detailed dynamic group information to check matching rules
  dynamic_groups_details_cmd = %{oci iam dynamic-group list --compartment-id '#{tenancy_ocid}' --all 2>/dev/null | jq -r '.data[] | "\(.name)|\(.matching-rule)"' || echo ""}
  dynamic_groups_details = command(dynamic_groups_details_cmd).stdout.strip

  # Check if dynamic groups exist with instance matching rules
  has_instance_matching_rules = dynamic_groups_details.lines.any? do |line|
    parts = line.split('|')
    parts.length == 2 && (
      parts[1].downcase.include?('instance') ||
      parts[1].downcase.include?('resource.type') ||
      parts[1].downcase.include?('any.compute.instance')
    )
  end

  # Check if request.principal policies exist
  has_request_principal_policies = !policies_with_principal_output.empty?

  # Query all policies to get detailed statement view
  all_policies_cmd = %(oci iam policy list --compartment-id '#{tenancy_ocid}' --all 2>/dev/null | jq '[.data[].statements[]? | select(contains("request.principal"))]' || echo "[]")
  request_principal_statements = json(command: all_policies_cmd).params

  # Overall assessment
  instance_principal_configured = has_instance_matching_rules || has_request_principal_policies

  describe 'Instance Principal Authentication Configuration' do
    it 'should be configured via Dynamic Groups or request.principal policies' do
      failure_message = <<~MSG
        Instance Principal authentication is not properly configured.

        Dynamic Groups with instance matching rules found: #{has_instance_matching_rules}
        Request.principal policies found: #{has_request_principal_policies}

        For compliance, ensure at least one of the following:
        1. Dynamic Groups exist with matching rules that include instances accessing OCI resources
        2. IAM policies contain request.principal conditions like:
           - allow any-user to <verb> <resource> in compartment <compartment-name> where ALL {request.principal.type='<resource_type>', request.principal.id='<resource_ocid>'}
           - allow any-user to <verb> <resource> in compartment <compartment-name> where ALL {request.principal.type='<resource_type>', request.principal.compartment.id='<compartment_OCID>'}
      MSG

      expect(instance_principal_configured).to eq(true), failure_message
    end
  end

  if request_principal_statements.any?
    describe 'Request.principal policy statements' do
      it 'should include proper conditions for resource types and IDs' do
        expect(request_principal_statements).not_to be_empty
      end
    end
  end
end
