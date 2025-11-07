control '4_1' do
  title 'Ensure default tags are used on resources'

  desc <<~DESC
    "Using default
  DESC

  desc 'check', <<~CHECK
    %q(From Console: Login to OCI Console. From the navigation menu, select Identity &
    Security . Under Identity , select Compartments . Click the name of the root compartment.
    Under Resources , select Tag Defaults . In the Tag Defaults table, verify that there is a
    Tag with a value of ${iam.principal.name} and a Tag Key Status of Active . Note: The name
    of the
  CHECK

  desc 'fix', <<~FIX
    'From Console: Login to OCI Console. From the navigation menu, select Governance &
    Administration . Under Tenancy Management , select Tag Namespaces . Under Compartment ,
    select the root compartment. If no
  FIX

  desc 'potential_impacts', <<~POTENTIAL_IMPACTS
    "There is no performance
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
end
