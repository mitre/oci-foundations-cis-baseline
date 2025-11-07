control "4_9" do
  title "Ensure a notification is configured for  changes to route tables"
  desc "It is recommended to setup an Event Rule and Notification that gets triggered when route tables are created, updated or deleted. Event Rules are compartment scoped and will detect events in child compartments, it is recommended to create the Event rule at the root compartment level.

Route tables control traffic flowing to or from Virtual Cloud Networks and Subnets.
Monitoring and alerting on changes to route tables will help in identifying changes these traffic flows."
  desc "check", %q(From Console: Go to the Events Service page: https://cloud.oracle.com/events/rules Select the Compartment that hosts the rules Find and click the Rule that handles Route Table Changes (if any) Click the Edit Rule button and verify that the RuleConditions section contains a condition for the Service Networking and Event Types: Route Table – Change Compartment , Route Table – Create , Route Table - Delete and Route Table - Update Verify that in the Actions section the Action Type contains: Notifications and that a valid Topic is referenced. From CLI: Find the  OCID of the specific Event Rule based on Display Name and Compartment OCID oci events rule list --compartment-id <compartment-ocid> --query "data [?\"display-name\"=='<display-name>']".{"id:id"} --output table List the details of a specific Event Rule based on the OCID of the rule. oci events rule get --rule-id <rule-id> In the JSON output locate the Conditions key value pair and verify that the following Conditions are present: com.oraclecloud.virtualnetwork.changeroutetablecompartment
com.oraclecloud.virtualnetwork.createroutetable
com.oraclecloud.virtualnetwork.deleteroutetable
com.oraclecloud.virtualnetwork.updateroutetable Verify the value of the is-enabled attribute is true In the JSON output verify that actionType is ONS and locate the topic-id Verify the correct topic is used by checking the topic name oci ons topic get --topic-id <topic-id> --query data.{"name:name"} --output table)
  desc "fix", %q(From Console: Go to the Events Service page: https://cloud.oracle.com/events/rules Select the compartment that should host the rule Click Create Rule Provide a Display Name and Description Create a Rule Condition by selecting Networking in the Service Name Drop-down and selecting Route Table – Change Compartment , Route Table – Create , Route Table - Delete and Route Table – Update In the Actions section select Notifications as Action Type Select the Compartment that hosts the Topic to be used. Select the Topic to be used Optionally add Tags to the Rule Click Create Rule From CLI: Find the topic-id of the topic the Event Rule should use for sending Notifications by using the topic name and Compartment OCID oci ons topic list --compartment-id <compartment-ocid> --all --query "data [?name=='<topic-name>']".{"name:name,topic_id:\"topic-id\""} --output table Create a JSON file to be used when creating the Event Rule. Replace topic id, display name, description and compartment OCID. {
    "actions":
    {
        "actions": [
        {
            "actionType": "ONS",
            "isEnabled": true,
            "topicId": "<topic-id>"
        }]
    },
    "condition":
"{\"eventType\":[\"com.oraclecloud.virtualnetwork.changeroutetablecompartment\",\"com.oraclecloud.virtualnetwork.createroutetable\",\"com.oraclecloud.virtualnetwork.deleteroutetable\",\"com.oraclecloud.virtualnetwork.updateroutetable\"],\"data\":{}}",
    "displayName": "<display-name>",
    "description": "<description>",
    "isEnabled": true,
    "compartmentId": "<compartment-ocid>"
} Create the actual event rule oci events rule create --from-json file://event_rule.json Note in the JSON returned that it lists the parameters specified in the JSON file provided and that there is an OCID provided for the Event Rule)
  desc "mitigations", "The same Notification topic can be reused by many Event Rules. The generated notification will include an eventID that can be used when querying the Audit Logs in case further investigation is required."
  desc "potential_impacts", "There is no performance impact when enabling the above described features but depending on the amount of notifications sent per month there may be a cost associated."
  impact 0.5
  tag check_id: "C-4_9"
  tag severity: "medium"
  tag gid: "CIS-4_9"
  tag rid: "xccdf_cis_cis_rule_4_9"
  tag stig_id: "4.9"
  tag gtitle: "<GroupDescription></GroupDescription>"
  tag "documentable"
  tag cci: ["CCI-002323", "CCI-000364", "CCI-000366", "CCI-000381", "CCI-001199", "CCI-000540", "CCI-002472"]
  tag nist: ["AC-18 a", "CM-6 a", "CM-6 b", "CM-7 a", "SC-28", "CP-9 (d)", "SC-28"]
end
