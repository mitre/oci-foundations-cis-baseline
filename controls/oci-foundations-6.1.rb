control 'oci-foundations-6.1' do
  title 'Create at least one compartment in your tenancy to store cloud resources'

  desc <<~DESC
    When you sign up for Oracle Cloud Infrastructure, Oracle creates your tenancy, which is
    the root compartment that holds all your cloud resources. You then create additional
    compartments within the tenancy (root compartment) and corresponding policies to control
    access to the resources in each compartment. Compartments allow you to organize and
    control access to your cloud resources. A compartment is a collection of related resources
    (such as instances, databases, virtual cloud networks, block volumes) that can be accessed
    only by certain groups that have been given permission by an administrator. Compartments
    are a logical group that adds an extra layer of isolation, organization and authorization
    making it harder for unauthorized users to gain access to OCI resources.
  DESC

  desc 'check', <<~CHECK
    From Console: Login into the OCI Console. Click in the search bar, top of the screen. Type

    Advanced Resource Query and hit enter . Click the Advanced Resource Query button in the
    upper right of the screen. Enter the following query in the query box: query compartment
    resources where (compartmentId='<tenancy-id>' && lifecycleState='ACTIVE') Ensure query
    returns at least one compartment in addition to the ManagedCompartmentForPaaS compartment

    From CLI: Execute the following command oci search resource structured-search --query-text

    "query compartment resources where (compartmentId='<tenancy-id>' &&
    lifecycleState='ACTIVE')" Ensure items are returned.
  CHECK

  desc 'fix', <<~FIX
    From Console: Login to OCI Console. Select Identity from the Services menu. Select

    Compartments from the Identity menu. Click Create Compartment Enter a Name Enter a
    Description Select the root compartment as the Parent Compartment Click Create Compartment

    From CLI: Execute the following command oci iam compartment create --compartment-id

    '<tenancy-id>' --name '<compartment-name>' --description '<compartment description>'
  FIX

  desc 'potential_impacts', <<~POTENTIAL_IMPACTS
    Once the compartment is created an OCI IAM policy must be created to allow a group to
    resources in the compartment otherwise only group with tenancy access will have access.
  POTENTIAL_IMPACTS

  impact 0.5

  tag severity: 'medium'
  tag benchmark_ref: '6.1'
  tag cis_level: 'Level 1'
  tag assessment_status: 'Automated'
  tag cis_controls: %w[3.1]

  tag cci: %w[CCI-001315]

  tag nist: ['SI-12']

  tenancy_ocid = input('tenancy_ocid')

  compartments_response = json(command: %(oci iam compartment list --compartment-id "#{tenancy_ocid}" --access-level ACCESSIBLE --all 2>/dev/null))
  compartments = compartments_response.params.fetch('data', [])
  active_top_level_compartments = compartments.select { |compartment| compartment['lifecycle-state'] == 'ACTIVE' }

  findings = []
  if active_top_level_compartments.empty?
    discovered_compartments = active_top_level_compartments.map do |compartment|
      "#{compartment['name']} (#{compartment['id']})"
    end

    findings << <<~ENTRY.chomp
      Issue: No ACTIVE customer-created top-level compartments found.
      Tenancy OCID: #{tenancy_ocid}
      Active Top-level Compartments: #{discovered_compartments.empty? ? 'None' : discovered_compartments.join(', ')}
    ENTRY
  end

  numbered_findings = findings.each_with_index.map do |entry, index|
    "[#{index + 1}]\n#{entry}"
  end

  describe 'Top-level tenancy compartments' do
    it 'should include at least one ACTIVE customer-created compartment' do
      expect(findings).to be_empty, <<~MSG
        Non-compliant findings:

        #{numbered_findings.join("\n\n")}
      MSG
    end
  end
end
