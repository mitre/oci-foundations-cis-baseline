control '6_2' do
  title 'Ensure no resources are created in the root compartment'

  desc <<~DESC
    When you create a cloud resource such as an instance, block volume, or cloud network, you
    must specify to which compartment you want the resource to belong. Placing resources in
    the root compartment makes it difficult to organize and isolate those resources. Placing
    resources into a compartment will allow you to organize and have more granular access
    controls to your cloud resources.
  DESC

  desc 'check', <<~CHECK
    From Console: Login into the OCI Console. Click in the search bar, top of the screen. Type
    
    Advance Resource Query and hit enter . Click the Advanced Resource Query button in the
    upper right of the screen. Enter the following query into the query box: query VCN,
    instance, bootvolume, volume, filesystem, bucket, autonomousdatabase, database, dbsystem
    resources where compartmentId = '<tenancy-id>' Ensure query returns no results. From CLI:
    
    Execute the following command: oci search resource structured-search --query-text "query
    VCN, instance, volume, bootvolume, filesystem, bucket, autonomousdatabase, database,
    dbsystem resources where compartmentId = '<tenancy-id>'" Ensure query return no results.
  CHECK

  desc 'fix', <<~FIX
    From Console: Follow audit procedure above. For each item in the returned results, click
    
    the item name. Then select Move Resource or More Actions then Move Resource . Select a
    compartment that is not the root compartment in CHOOSE NEW COMPARTMENT . Click Move
    Resource . From CLI: Follow the audit procedure above. For each bucket item execute the
    below command: oci os bucket update --bucket-name <bucket-name> --compartment-id <not root
    compartment-id> For other resources use the change-compartment command for the resource
    type: oci <service-command> <resource-command> change-compartment --<item-id> <item-id>
    --compartment-id <not root compartment-id> i. Example for an Autonomous Database: oci db
    autonomous-database change-compartment --autonomous-database-id <autonmous-database-id>
    --compartment-id <not root compartment-id>
  FIX

  desc 'potential_impacts', <<~POTENTIAL_IMPACTS
    "Placing a resource in a compartment will
  POTENTIAL_IMPACTS

  impact 0.5

  tag check_id: 'C-6_2'
  tag severity: 'medium'
  tag gid: 'CIS-6_2'
  tag rid: 'xccdf_cis_cis_rule_6_2'
  tag stig_id: '6.2'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag 'documentable'

  tag cci: [
    'CCI-000051',
    'CCI-002856',
    'CCI-003205',
    'CCI-000050'
  ]

  tag nist: [
    'AC-8 a',
    'CP-12',
    'SA-12 (8)',
    'AC-8 b'
  ]
end
