control 'oci-foundations-4.4' do
  title 'Ensure a notification is configured for IdP group mapping changes'

  desc <<~DESC
    It is recommended to setup an Event Rule and Notification that gets triggered when
    Identity Provider Group Mappings are created, updated or deleted. Event Rules are
    compartment scoped and will detect events in child compartments. It is recommended to
    create the Event rule at the root compartment level. IAM Policies govern access to all
    resources within an OCI Tenancy. IAM Policies use OCI Groups for assigning the privileges.
    Identity Provider Groups could be mapped to OCI Groups to assign privileges to federated
    users in OCI. Monitoring and alerting on changes to Identity Provider Group mappings will
    help in identifying changes to the security posture.
  DESC

  desc 'check', <<~CHECK
    From Console: Go to the Events Service page: https://cloud.oracle.com/events/rules Select

    the Compartment that hosts the rules Find and click the Rule that handles Idp Group
    Mapping Changes (if any) Click the Edit Rule button and verify that the RuleConditions
    section contains a condition for the Service Identity and Event Types: Idp Group Mapping –
    Create , Idp Group Mapping – Delete and Idp Group Mapping – Update Verify that in the
    Actions section the Action Type contains: Notifications and that a valid Topic is
    referenced. From CLI: Find the OCID of the specific Event Rule based on Display Name and
    Compartment OCID oci events rule list --compartment-id <compartment-ocid> --query "data
    [?"display-name"=='<displa-name>']".{"id:id"} --output table List the details of a
    specific Event Rule based on the OCID of the rule. oci events rule get --rule-id <rule-id>
    In the JSON output locate the Conditions key value pair and verify that the following
    Conditions are present: com.oraclecloud.identitycontrolplane.createidpgroupmapping
    com.oraclecloud.identitycontrolplane.deleteidpgroupmapping
    com.oraclecloud.identitycontrolplane.updateidpgroupmapping Verify the value of the
    is-enabled attribute is true In the JSON output verify that actionType is ONS and locate
    the topic-id Verify the correct topic is used by checking the topic name oci ons topic get
    --topic-id <topic-id> --query data.{"name:name"} --output table
  CHECK

  desc 'fix', <<~FIX
    From Console: Go to the Events Service page: https://cloud.oracle.com/events/rules Select

    the compartment that should host the rule Click Create Rule Provide a Display Name and
    Description Create a Rule Condition by selecting Identity in the Service Name Drop-down
    and selecting Idp Group Mapping – Create , Idp Group Mapping – Delete and Idp Group
    Mapping – Update In the Actions section select Notifications as Action Type Select the
    Compartment that hosts the Topic to be used. Select the Topic to be used Optionally add
    Tags to the Rule Click Create Rule From CLI: Find the topic-id of the topic the Event Rule
    should use for sending notifications by using the topic name and Compartment OCID oci ons
    topic list --compartment-id <compartment-ocid> --all --query "data
    [?name=='<topic-name>']".{"name:name,topic_id:"topic-id""} --output table Create a JSON
    file to be used when creating the Event Rule. Replace topic id, display name, description
    and compartment OCID. { "actions": { "actions": [ { "actionType": "ONS", "isEnabled":

    true, "topicId": "<topic-id>" }] }, "condition":

    "{"eventType":["com.oraclecloud.identitycontrolplane.createidpgroupmapping","com.oraclecloud.identitycontrolplane.deleteidpgroupmapping","com.oraclecloud.identitycontrolplane.updateidpgroupmapping"],"data":{}}",
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

  tag severity: 'medium'
  tag benchmark_ref: '4.4'
  tag cis_level: 'Level 1'
  tag assessment_status: 'Automated'

  tag cci: %w[CCI-002641]

  tag nist: ['SI-4']

  required_event_types = [
    'com.oraclecloud.identitycontrolplane.addidpgroupmapping',
    'com.oraclecloud.identitycontrolplane.removeidpgroupmapping',
    'com.oraclecloud.identitycontrolplane.updateidpgroupmapping'
  ]

  tenancy_ocid = input('tenancy_ocid')
  topic_name = input('group_mapping_notification_topic')

  rules = oci_event_rules(compartment_id: tenancy_ocid)
  missing = rules.missing_regions(required_event_types: required_event_types, topic_name: topic_name)

  describe 'IdP group mapping change notifications' do
    it 'should have enabled event rules with an active ONS topic in all regions' do
      expect(missing).to be_empty,
                         "Regions missing compliant event rules: #{missing.join(', ')}"
    end
  end
end
