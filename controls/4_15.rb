control '4_15' do
  title 'Ensure a notification is configured for Oracle Cloud Guard problems detected'
  desc 'Cloud Guard detects misconfigured resources and insecure activity within a tenancy and provides security administrators with the visibility to resolve these issues. Upon detection, Cloud Guard generates a Problem. It is recommended to setup an Event Rule and Notification that gets triggered when Oracle Cloud Guard Problems are created, dismissed or remediated. Event Rules are compartment scoped and will detect events in child compartments. It is recommended to create the Event rule at the root compartment level.

Cloud Guard provides an automated means to monitor a tenancy for resources that are configured in an insecure manner as well as risky network activity from these resources. Monitoring and alerting on Problems detected by Cloud Guard will help in identifying changes to the security posture.'
  desc 'check', %q(From Console: Go to the Events Service page: https://cloud.oracle.com/events/rules Select the Compartment that hosts the rules Find and click the Rule that handles Cloud Guard Changes (if any) Click the Edit Rule button and verify that the RuleConditions section contains a condition for the Service Cloud Guard and Event Types:  Detected – Problem, Remediated – Problem, and Dismissed - Problem Verify that in the Actions section the Action Type contains: Notifications and that a valid Topic is referenced. From CLI: Find the OCID of the specific Event Rule based on Display Name and Compartment OCID oci events rule list --compartment-id=<compartment OCID> --query "data [?\"display-name\"=='<display name used>']".{"id:id"} --output table List the details of a specific Event Rule based on the OCID of the rule. In the JSON output locate the Conditions key-value pair and verify that the following Conditions are present: "com.oraclecloud.cloudguard.problemdetected","com.oraclecloud.cloudguard.problemdismissed","com.oraclecloud.cloudguard.problemremediated" Verify the value of the is-enabled attribute is true In the JSON output verify that actionType is ONS and locate the topic-id Verify the correct topic is used by checking the topic name oci ons topic get --topic-id=<topic id> --query data.{"name:name"} --output table)
  desc 'fix', %q(From Console: Go to the Events Service page: https://cloud.oracle.com/events/rules Select the compartment that should host the rule Click Create Rule Provide a Display Name and Description Create a Rule Condition by selecting Cloud Guard in the Service Name Drop-down and selecting: Detected – Problem , Remediated – Problem , and Dismissed - Problem In the Actions section select Notifications as Action Type Select the Compartment that hosts the Topic to be used. Select the Topic to be used Optionally add Tags to the Rule Click Create Rule From CLI: Find the topic-id of the topic the Event Rule should use for sending Notifications by using the topic name and Compartment OCID oci ons topic list --compartment-id=<compartment OCID> --all --query "data [?name=='<topic_name>']".{"name:name,topic_id:\"topic-id\""} --output table Create a JSON file to be used when creating the Event Rule. Replace topic id, display name, description and compartment OCID. {
    "actions":
    {
        "actions": [
        {
            "actionType": "ONS",
            "isEnabled": true,
            "topicId": "<topic id>"
        }]
    },
    "condition":
"{\"eventType\":[\" com.oraclecloud.cloudguard.problemdetected\",\" com.oraclecloud.cloudguard.problemdismissed\",\" com.oraclecloud.cloudguard.problemremediated\"],\"data\":{}}",
    "displayName": "<display name>",
    "description": "<description>",
    "isEnabled": true,
    "compartmentId": "compartment OCID"
} Create the actual event rule oci events rule create --from-json file://event_rule.json Note in the JSON returned that it lists the parameters specified in the JSON file provided and that there is an OCID provided for the Event Rule)
  desc 'mitigations', 'Your tenancy might have a different Cloud Reporting region than your home region. The same Notification topic can be reused by many Event Rules. The generated notification will include an eventID that can be used when querying the Audit Logs in case further investigation is required.'
  desc 'potential_impacts', 'There is no performance impact when enabling the above described features but depending on the amount of notifications sent per month there may be a cost associated.'
  impact 0.5
  tag check_id: 'C-4_15'
  tag severity: 'medium'
  tag gid: 'CIS-4_15'
  tag rid: 'xccdf_cis_cis_rule_4_15'
  tag stig_id: '4.15'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag 'documentable'
  tag cci: ['CCI-000123', 'CCI-000169', 'CCI-000172', 'CCI-000126', 'CCI-000133', 'CCI-000134', 'CCI-001875', 'CCI-000135']
  tag nist: ['AU-2 a', 'AU-12 a', 'AU-12 c', 'AU-2 c', 'AU-3 d', 'AU-3 e', 'AU-7 a', 'AU-3 (1)']
end
