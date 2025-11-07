control '4_5' do
  title 'Ensure a notification is configured for IAM group changes'

  desc <<~DESC
    It is recommended to setup an Event Rule and Notification that gets triggered when IAM
    Groups are created, updated or deleted. Event Rules are compartment scoped and will detect
    events in child compartments, it is recommended to create the Event rule at the root
    compartment level. IAM Groups control access to all resources within an OCI Tenancy.
    Monitoring and alerting on changes to IAM Groups will help in identifying changes to
    satisfy least privilege principle.
  DESC

  desc 'check', <<~CHECK
    From Console: Go to the Events Service page: https://cloud.oracle.com/events/rules Select
    
    the Compartment that hosts the rules Find and click the Rule that handles IAM Group
    Changes Click the Edit Rule button and verify that the Rule Conditions section contains a
    condition for the Service Identity and Event Types: Group – Create , Group – Delete and
    Group – Update Verify that in the Actions section the Action Type contains: Notifications
    and that a valid Topic is referenced. From CLI: Find the OCID of the specific Event Rule
    based on Display Name and Compartment OCID oci events rule list --compartment-id
    <compartment-ocid> --query "data [?\"display-name\"=='<display-name>']".{"id:id"} --output
    table List the details of a specific Event Rule based on the OCID of the rule. oci events
    rule get --rule-id <rule-id> In the JSON output locate the Conditions key value pair and
    verify that the following Conditions are present:
    
    com.oraclecloud.identitycontrolplane.creategroup
    com.oraclecloud.identitycontrolplane.deletegroup
    com.oraclecloud.identitycontrolplane.updategroup Verify the value of the is-enabled
    attribute is true In the JSON output verify that actionType is ONS and locate the topic-id
    Verify the correct topic is used by checking the topic name oci ons topic get --topic-id
    <topic-id> --query data.{"name:name"} --output table
  CHECK

  desc 'fix', <<~FIX
    From Console: Go to the Events Service page: https://cloud.oracle.com/events/rules Select
    
    the compartment that should host the rule Click Create Rule Provide a Display Name and
    Description Create a Rule Condition by selecting Identity in the Service Name Drop-down
    and selecting Group – Create , Group – Delete and Group – Update In the Actions section
    select Notifications as Action Type Select the Compartment that hosts the Topic to be
    used. Select the Topic to be used Optionally add Tags to the Rule Click Create Rule From
    CLI: Find the topic-id of the topic the Event Rule should use for sending Notifications by
    using the topic name and Compartment OCID oci ons topic list --compartment-id
    <compartment-ocid> --all --query "data
    [?name=='<topic-name>']".{"name:name,topic_id:\"topic-id\""} --output table Create a JSON
    file to be used when creating the Event Rule. Replace topic id, display name, description
    and compartment OCID. { "actions": { "actions": [ { "actionType": "ONS", "isEnabled":
    
    true, "topicId": "<topic-id>" }] }, "condition":
    
    "{\"eventType\":[\"com.oraclecloud.identitycontrolplane.creategroup\",\"com.oraclecloud.identitycontrolplane.deletegroup\",\"com.oraclecloud.identitycontrolplane.updategroup\"],\"data\":{}}",
    "displayName": "<display-name>", "description": "<description>", "isEnabled": true,
    "compartmentId": "<compartment-ocid>" } Create the actual event rule oci events rule
    create --from-json file://event_rule.json Note in the JSON returned that it lists the
    parameters specified in the JSON file provided and that there is an OCID provided for the
    Event Rule
  FIX

  desc 'potential_impacts', <<~POTENTIAL_IMPACTS
    "There is no performance
  POTENTIAL_IMPACTS

  impact 0.5

  tag check_id: 'C-4_5'
  tag severity: 'medium'
  tag gid: 'CIS-4_5'
  tag rid: 'xccdf_cis_cis_rule_4_5'
  tag stig_id: '4.5'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag 'documentable'

  tag cci: [
    'CCI-002323',
    'CCI-000364',
    'CCI-000366',
    'CCI-000381',
    'CCI-001199',
    'CCI-000540',
    'CCI-002472'
  ]

  tag nist: [
    'AC-18 a',
    'CM-6 a',
    'CM-6 b',
    'CM-7 a',
    'SC-28',
    'CP-9 (d)',
    'SC-28'
  ]
end
