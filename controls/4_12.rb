control '4_12' do
  title 'Ensure a notification is configured for changes to network gateways'
  desc 'It is recommended to setup an Event Rule and Notification that gets triggered when Network Gateways are created, updated, deleted, attached, detached, or moved. This recommendation includes Internet Gateways, Dynamic Routing Gateways, Service Gateways, Local Peering Gateways, and NAT Gateways. Event Rules are compartment scoped and will detect events in child compartments, it is recommended to create the Event rule at the root compartment level.

Network Gateways act as routers between VCNs and the Internet, Oracle Services Networks, other VCNS, and on-premise networks.
Monitoring and alerting on changes to Network Gateways will help in identifying changes to the security posture.'
  desc 'check', %q(From Console: Go to the Events Service page: https://cloud.oracle.com/events/rules Select the Compartment that hosts the rules Find and click the Rule that handles Network Gateways Changes (if any) Click the Edit Rule button and verify that the RuleConditions section contains a condition for the Service Networking and Event Types: DRG – Create
DRG – Delete
DRG – Update
DRG Attachment – Create
DRG Attachment – Delete
DRG Attachment – Update
Internet Gateway – Create
Internet Gateway – Delete
Internet Gateway – Update
Internet Gateway – Change Compartment
Local Peering Gateway – Create
Local Peering Gateway – Delete End
Local Peering Gateway – Update
Local Peering Gateway – Change Compartment
NAT Gateway – Create
NAT Gateway – Delete
NAT Gateway – Update
NAT Gateway – Change Compartment
Service Gateway – Create
Service Gateway – Delete End
Service Gateway – Update
Service Gateway – Attach Service
Service Gateway – Detach Service
Service Gateway – Change Compartment Verify that in the Actions section the Action Type contains: Notifications and that a valid Topic is referenced. From CLI: Find the OCID of the specific Event Rule based on Display Name and Compartment OCID oci events rule list --compartment-id <compartment-ocid> --query "data [?\"display-name\"=='<display-name>']".{"id:id"} --output table List the details of a specific Event Rule based on the OCID of the rule. oci events rule get --rule-id <rule-id> In the JSON output locate the Conditions key value pair and verify that the following Conditions are present: com.oraclecloud.virtualnetwork.createdrg
com.oraclecloud.virtualnetwork.deletedrg
com.oraclecloud.virtualnetwork.updatedrg
com.oraclecloud.virtualnetwork.createdrgattachment
com.oraclecloud.virtualnetwork.deletedrgattachment
com.oraclecloud.virtualnetwork.updatedrgattachment
com.oraclecloud.virtualnetwork.changeinternetgatewaycompartment
com.oraclecloud.virtualnetwork.createinternetgateway
com.oraclecloud.virtualnetwork.deleteinternetgateway
com.oraclecloud.virtualnetwork.updateinternetgateway
com.oraclecloud.virtualnetwork.changelocalpeeringgatewaycompartment
com.oraclecloud.virtualnetwork.createlocalpeeringgateway
com.oraclecloud.virtualnetwork.deletelocalpeeringgateway.end
com.oraclecloud.virtualnetwork.updatelocalpeeringgateway
com.oraclecloud.natgateway.changenatgatewaycompartment
com.oraclecloud.natgateway.createnatgateway
com.oraclecloud.natgateway.deletenatgateway
com.oraclecloud.natgateway.updatenatgateway
com.oraclecloud.servicegateway.attachserviceid
com.oraclecloud.servicegateway.changeservicegatewaycompartment
com.oraclecloud.servicegateway.createservicegateway
com.oraclecloud.servicegateway.deleteservicegateway.end
com.oraclecloud.servicegateway.detachserviceid
com.oraclecloud.servicegateway.updateservicegateway Verify the value of the is-enabled attribute is true In the JSON output verify that actionType is ONS and locate the topic-id Verify the correct topic is used by checking the topic name oci ons topic get --topic-id <topic-id> --query data.{"name:name"} --output table)
  desc 'fix', %q(From Console: Go to the Events Service page: https://cloud.oracle.com/events/rules Select the compartment that should host the rule Click Create Rule Provide a Display Name and Description Create a Rule Condition by selecting Networking in the Service Name Drop-down and selecting: DRG – Create
DRG – Delete
DRG – Update
DRG Attachment – Create
DRG Attachment – Delete
DRG Attachment – Update
Internet Gateway – Create
Internet Gateway – Delete
Internet Gateway – Update
Internet Gateway – Change Compartment
Local Peering Gateway – Create
Local Peering Gateway – Delete End
Local Peering Gateway – Update
Local Peering Gateway – Change Compartment
NAT Gateway – Create
NAT Gateway – Delete
NAT Gateway – Update
NAT Gateway – Change Compartment
Service Gateway – Create
Service Gateway – Delete End
Service Gateway – Update
Service Gateway – Attach Service
Service Gateway – Detach Service
Service Gateway – Change Compartment In the Actions section select Notifications as Action Type Select the Compartment that hosts the Topic to be used. Select the Topic to be used Optionally add Tags to the Rule Click Create Rule From CLI: Find the topic-id of the topic the Event Rule should use for sending Notifications by using the topic name and Compartment OCID oci ons topic list --compartment-id <compartment-ocid> --all --query "data [?name=='<topic_name>']".{"name:name,topic_id:\"topic-id\""} --output table Create a JSON file to be used when creating the Event Rule. Replace topic id, display name, description and compartment OCID. {
    "actions": {
        "actions": [
            {
                "actionType": "ONS",
                "isEnabled": true,
                "topicId": "<topic-id>"
           }
        ]
    },
    "condition":
"{\"eventType\":[\"com.oraclecloud.virtualnetwork.createdrg\",\"com.oraclecloud.virtualnetwork.deletedrg\",\"com.oraclecloud.virtualnetwork.updatedrg\",\"com.oraclecloud.virtualnetwork.createdrgattachment\",\"com.oraclecloud.virtualnetwork.deletedrgattachment\",\"com.oraclecloud.virtualnetwork.updatedrgattachment\",\"com.oraclecloud.virtualnetwork.changeinternetgatewaycompartment\",\"com.oraclecloud.virtualnetwork.createinternetgateway\",\"com.oraclecloud.virtualnetwork.deleteinternetgateway\",\"com.oraclecloud.virtualnetwork.updateinternetgateway\",\"com.oraclecloud.virtualnetwork.changelocalpeeringgatewaycompartment\",\"com.oraclecloud.virtualnetwork.createlocalpeeringgateway\",\"com.oraclecloud.virtualnetwork.deletelocalpeeringgateway.end\",\"com.oraclecloud.virtualnetwork.updatelocalpeeringgateway\",\"com.oraclecloud.natgateway.changenatgatewaycompartment\",\"com.oraclecloud.natgateway.createnatgateway\",\"com.oraclecloud.natgateway.deletenatgateway\",\"com.oraclecloud.natgateway.updatenatgateway\",\"com.oraclecloud.servicegateway.attachserviceid\",\"com.oraclecloud.servicegateway.changeservicegatewaycompartment\",\"com.oraclecloud.servicegateway.createservicegateway\",\"com.oraclecloud.servicegateway.deleteservicegateway.end\",\"com.oraclecloud.servicegateway.detachserviceid\",\"com.oraclecloud.servicegateway.updateservicegateway\"],\"data\":{}}",
    "displayName": "<display-name>",
    "description": "<description>",
    "isEnabled": true,
    "compartmentId": "<compartment-ocid>"
} Create the actual event rule oci events rule create --from-json file://event_rule.json Note in the JSON returned that it lists the parameters specified in the JSON file provided and that there is an OCID provided for the Event Rule)
  desc 'mitigations', 'The same Notification topic can be reused by many Event Rules. The generated notification will include an eventID that can be used when querying the Audit Logs in case further investigation is required.'
  desc 'potential_impacts', 'There is no performance impact when enabling the above described features but depending on the amount of notifications sent per month there may be a cost associated.'
  impact 0.5
  tag check_id: 'C-4_12'
  tag severity: 'medium'
  tag gid: 'CIS-4_12'
  tag rid: 'xccdf_cis_cis_rule_4_12'
  tag stig_id: '4.12'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag 'documentable'
  tag cci: ['CCI-002323', 'CCI-000364', 'CCI-000366', 'CCI-000381', 'CCI-001199', 'CCI-000540', 'CCI-002472']
  tag nist: ['AC-18 a', 'CM-6 a', 'CM-6 b', 'CM-7 a', 'SC-28', 'CP-9 (d)', 'SC-28']
end
