control 'oci-foundations-4.15' do
  title 'Ensure a notification is configured for Oracle Cloud Guard problems detected'

  desc <<~DESC
    Cloud Guard detects misconfigured resources and insecure activity within a tenancy and
    provides security administrators with the visibility to resolve these issues. Upon
    detection, Cloud Guard generates a Problem. It is recommended to setup an Event Rule and
    Notification that gets triggered when Oracle Cloud Guard Problems are created, dismissed
    or remediated. Event Rules are compartment scoped and will detect events in child
    compartments. It is recommended to create the Event rule at the root compartment level.
    Cloud Guard provides an automated means to monitor a tenancy for resources that are
    configured in an insecure manner as well as risky network activity from these resources.
    Monitoring and alerting on Problems detected by Cloud Guard will help in identifying
    changes to the security posture.
  DESC

  desc 'check', <<~CHECK
    From Console: Go to the Events Service page: https://cloud.oracle.com/events/rules Select

    the Compartment that hosts the rules Find and click the Rule that handles Cloud Guard
    Changes (if any) Click the Edit Rule button and verify that the RuleConditions section
    contains a condition for the Service Cloud Guard and Event Types: Detected – Problem,
    Remediated – Problem, and Dismissed - Problem Verify that in the Actions section the
    Action Type contains: Notifications and that a valid Topic is referenced. From CLI: Find
    the OCID of the specific Event Rule based on Display Name and Compartment OCID oci events
    rule list --compartment-id=<compartment OCID> --query "data [?"display-name"=='<display
    name used>']".{"id:id"} --output table List the details of a specific Event Rule based on
    the OCID of the rule. In the JSON output locate the Conditions key-value pair and verify
    that the following Conditions are present:

    "com.oraclecloud.cloudguard.problemdetected","com.oraclecloud.cloudguard.problemdismissed","com.oraclecloud.cloudguard.problemremediated"
    Verify the value of the is-enabled attribute is true In the JSON output verify that
    actionType is ONS and locate the topic-id Verify the correct topic is used by checking the
    topic name oci ons topic get --topic-id=<topic id> --query data.{"name:name"} --output
    table
  CHECK

  desc 'fix', <<~FIX
    From Console: Go to the Events Service page: https://cloud.oracle.com/events/rules Select

    the compartment that should host the rule Click Create Rule Provide a Display Name and
    Description Create a Rule Condition by selecting Cloud Guard in the Service Name Drop-down
    and selecting: Detected – Problem , Remediated – Problem , and Dismissed - Problem In the
    Actions section select Notifications as Action Type Select the Compartment that hosts the
    Topic to be used. Select the Topic to be used Optionally add Tags to the Rule Click Create
    Rule From CLI: Find the topic-id of the topic the Event Rule should use for sending
    Notifications by using the topic name and Compartment OCID oci ons topic list
    --compartment-id=<compartment OCID> --all --query "data
    [?name=='<topic_name>']".{"name:name,topic_id:"topic-id""} --output table Create a JSON
    file to be used when creating the Event Rule. Replace topic id, display name, description
    and compartment OCID. { "actions": { "actions": [ { "actionType": "ONS", "isEnabled":

    true, "topicId": "<topic id>" }] }, "condition": "{"eventType":["
    com.oraclecloud.cloudguard.problemdetected","
    com.oraclecloud.cloudguard.problemdismissed","
    com.oraclecloud.cloudguard.problemremediated"],"data":{}}", "displayName": "<display
    name>", "description": "<description>", "isEnabled": true, "compartmentId": "compartment
    OCID" } Create the actual event rule oci events rule create --from-json
    file://event_rule.json Note in the JSON returned that it lists the parameters specified in
    the JSON file provided and that there is an OCID provided for the Event Rule
  FIX

  desc 'potential_impacts', <<~POTENTIAL_IMPACTS
    "There is no performance
  POTENTIAL_IMPACTS

  impact 0.5

  tag severity: 'medium'
  tag benchmark_ref: '4.15'
  tag cis_level: 'Level 1'
  tag assessment_status: 'Automated'
  tag cis_controls: %w[8.2 8.11]

  tag cci: %w[CCI-000123 CCI-000133]

  tag nist: ['AU-2', 'AU-6']

  required_event_types = [
    'com.oraclecloud.cloudguard.problemdetected',
    'com.oraclecloud.cloudguard.problemdismissed',
    'com.oraclecloud.cloudguard.problemremediated'
  ]

  tenancy_ocid = input('tenancy_ocid')
  topic_name = input('cloud_guard_notification_topic')

  rules = oci_event_rules(compartment_id: tenancy_ocid)
  missing = rules.missing_regions(required_event_types: required_event_types, topic_name: topic_name)

  describe 'Oracle Cloud Guard problem notifications' do
    it 'should have enabled event rules with an active ONS topic in all regions' do
      expect(missing).to be_empty,
                         "Regions missing compliant event rules: #{missing.join(', ')}"
    end
  end
end
