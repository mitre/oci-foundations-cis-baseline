control '6_1' do
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

  tag check_id: 'C-6_1'
  tag severity: 'medium'
  tag gid: 'CIS-6_1'
  tag rid: 'xccdf_cis_cis_rule_6_1'
  tag stig_id: '6.1'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag 'documentable'

  tag cci: [
    'CCI-001315',
    'CCI-001678',
    'CCI-000167'
  ]

  tag nist: [
    'SI-12',
    'SI-12',
    'AU-11'
  ]
end
