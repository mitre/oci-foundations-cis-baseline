control 'oci-foundations-4.18' do
  title 'Ensure a notification is configured for Local OCI User Authentication'

  desc <<~DESC
    "It is recommended that an Event Rule and Notification be set up when a user in the via
    OCI local authentication. Event Rules are compartment-scoped and will detect events in
    child compartments. This Event rule is required to be created at the root compartment
    level. Users should rarely use OCI local authenticated and be authenticated via
    organizational standard Identity providers, not local credentials. Access in this matter
    would represent a break glass activity and should be monitored to see if changes made
  DESC

  desc 'check', <<~CHECK
    From Console: Go to the Events Service page: https://cloud.oracle.com/events/rules Select

    the Root Compartment that hosts the rules Click the Rule that handles Identity SignOn
    Changes (if any) Click the Edit Rule button and verify that the RuleCondition s section
    contains a condition Event Type for the Service Identity SignOn and Event Types:

    Interactive Login On the Action Type contains: Notifications and that a valid Topic is
    referenced. From CLI: Find the OCID of the specific Event Rule based on Display Name and
    Tenancy OCID oci events rule list --compartment-id <tenancy-ocid> --query "data
    [?"display-name"=='<display-name>']".{"id:id"} --output table List the details of a
    specific Event Rule based on the OCID of the rule. oci events rule get --rule-id <rule-id>
    In the JSON output locate the Conditions key value pair and verify that the following
    Conditions are present: com.oraclecloud.identitysignon.interactivelogin Verify the value
    of the is-enabled attribute is true In the JSON output verify that actionType is ONS and
    locate the topic-id Verify the correct topic is used by checking the topic name oci ons
    topic get --topic-id <topic-id> --query data.{"name:name"} --output table
  CHECK

  desc 'fix', <<~FIX
    From Console: Go to the Events Service page: https://cloud.oracle.com/events/rules Select

    the Root compartment that should host the rule Click Create Rule Provide a Display Name
    and Description Create a Rule Condition by selecting Identity SignOn in the Service Name
    Drop-down and selecting Interactive Login In the Actions section select Notifications as
    Action Type Select the Compartment that hosts the Topic to be used. Select the Topic to be
    used Optionally add Tags to the Rule Click Create Rule From CLI: Find the topic-id of the
    topic the Event Rule should use for sending notifications by using the topic name and
    Tenancy OCID oci ons topic list --compartment-id <tenacy-ocid> --all --query "data
    [?name=='<topic-name>']".{"name:name,topic_id:"topic-id""} --output table Create a JSON
    file to be used when creating the Event Rule. Replace topic id, display name, description
    and compartment OCID. { "actions": { "actions": [ { "actionType": "ONS", "isEnabled":

    true, "topicId": "<topic-id>" }] }, "condition":

    "{"eventType":["com.oraclecloud.identitysignon.interactivelogin",data":{}}",
    "displayName": "<display-name>", "description": "<description>", "isEnabled": true,
    "compartmentId": "<tenancy-ocid>" } Create the actual event rule oci events rule create
    --from-json file://event_rule.json Note in the JSON returned that it lists the parameters
    specified in the JSON file provided and that there is an OCID provided for the Event Rule
  FIX

  desc 'potential_impacts', <<~POTENTIAL_IMPACTS
    "There is no performance
  POTENTIAL_IMPACTS

  impact 0.5

  tag severity: 'medium'
  tag benchmark_ref: '4.18'
  tag cis_level: 'Level 1'
  tag assessment_status: 'Automated'
  tag cis_controls: %w[8.11]

  tag cci: %w[CCI-000133]

  tag nist: ['AU-6']

  required_event_types = [
    'com.oraclecloud.identitysignon.interactivelogin'
  ]

  tenancy_ocid = input('tenancy_ocid')
  topic_name = input('identity_signon_notification_topic')

  rules = oci_event_rules(compartment_id: tenancy_ocid)
  missing = rules.missing_regions(required_event_types: required_event_types, topic_name: topic_name)

  describe 'Local OCI user authentication notifications' do
    it 'should have enabled event rules with an active ONS topic in all regions' do
      expect(missing).to be_empty,
                         "Regions missing compliant event rules: #{missing.join(', ')}"
    end
  end
end
