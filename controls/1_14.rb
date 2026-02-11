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

  compartments_response = json(command: 'oci iam compartment list --include-root --compartment-id-in-subtree TRUE --all 2>/dev/null')
  compartments_data = compartments_response.params.fetch('data', [])
  compartment_ids = compartments_data.map { |compartment| compartment['id'] }.compact.uniq
  compartment_names_by_id = compartments_data.each_with_object({}) do |compartment, map|
    compartment_id = compartment['id']
    next if compartment_id.to_s.empty?

    map[compartment_id] = compartment['name']
  end

  request_principal_statements = []

  compartment_ids.each do |compartment_id|
    policies_response = json(command: %(oci iam policy list --compartment-id "#{compartment_id}" --all 2>/dev/null))
    policies = policies_response.params.fetch('data', [])

    policies.each do |policy|
      policy_name = policy['name']
      policy_id = policy['id']

      Array(policy['statements']).each do |statement|
        normalized_statement = statement.to_s.strip
        next if normalized_statement.empty?
        next unless normalized_statement.match?(/request\.principal/i)

        request_principal_statements << {
          'compartment_id' => compartment_id,
          'compartment_name' => compartment_names_by_id[compartment_id],
          'policy_id' => policy_id,
          'policy_name' => policy_name,
          'statement' => normalized_statement
        }
      end
    end
  end

  findings = []

  malformed_statements = request_principal_statements.reject do |entry|
    statement = entry['statement']
    has_type = statement.match?(/request\.principal\.type/i)
    has_identifier = statement.match?(/request\.principal\.(?:id|compartment\.id)/i)
    has_type && has_identifier
  end

  malformed_statements.each do |entry|
    findings << entry.merge('issue' => 'Statement includes request.principal but is missing request.principal.type and/or request.principal.id/request.principal.compartment.id')
  end

  if request_principal_statements.empty?
    impact 0.0
    describe 'Ensure Instance Principal authentication is used for OCI instances, OCI Cloud Databases and OCI Functions to access OCI resources.' do
      skip 'No IAM policy statements with request.principal were found.'
    end
  else
    describe 'Ensure Instance Principal authentication is used for OCI instances, OCI Cloud Databases and OCI Functions to access OCI resources.' do
      subject { findings }
      it { should cmp [] }
    end
  end
end
