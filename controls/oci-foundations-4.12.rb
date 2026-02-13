control 'oci-foundations-4.12' do
  title 'Ensure a notification is configured for changes to network gateways'

  desc <<~DESC
    It is recommended to setup an Event Rule and Notification that gets triggered when Network
    Gateways are created, updated, deleted, attached, detached, or moved. This recommendation
    includes Internet Gateways, Dynamic Routing Gateways, Service Gateways, Local Peering
    Gateways, and NAT Gateways. Event Rules are compartment scoped and will detect events in
    child compartments, it is recommended to create the Event rule at the root compartment
    level. Network Gateways act as routers between VCNs and the Internet, Oracle Services
    Networks, other VCNS, and on-premise networks. Monitoring and alerting on changes to
    Network Gateways will help in identifying changes to the security posture.
  DESC

  desc 'check', <<~CHECK
    From Console: Go to the Events Service page: https://cloud.oracle.com/events/rules Select

    the Compartment that hosts the rules Find and click the Rule that handles Network Gateways
    Changes (if any) Click the Edit Rule button and verify that the RuleConditions section
    contains a condition for the Service Networking and Event Types: DRG – Create DRG – Delete
    DRG – Update DRG Attachment – Create DRG Attachment – Delete DRG Attachment – Update
    Internet Gateway – Create Internet Gateway – Delete Internet Gateway – Update Internet
    Gateway – Change Compartment Local Peering Gateway – Create Local Peering Gateway – Delete
    End Local Peering Gateway – Update Local Peering Gateway – Change Compartment NAT Gateway
    – Create NAT Gateway – Delete NAT Gateway – Update NAT Gateway – Change Compartment
    Service Gateway – Create Service Gateway – Delete End Service Gateway – Update Service
    Gateway – Attach Service Service Gateway – Detach Service Service Gateway – Change
    Compartment Verify that in the Actions section the Action Type contains: Notifications and
    that a valid Topic is referenced. From CLI: Find the OCID of the specific Event Rule based
    on Display Name and Compartment OCID oci events rule list --compartment-id
    <compartment-ocid> --query "data [?"display-name"=='<display-name>']".{"id:id"} --output
    table List the details of a specific Event Rule based on the OCID of the rule. oci events
    rule get --rule-id <rule-id> In the JSON output locate the Conditions key value pair and
    verify that the following Conditions are present: com.oraclecloud.virtualnetwork.createdrg
    com.oraclecloud.virtualnetwork.deletedrg com.oraclecloud.virtualnetwork.updatedrg
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
    com.oraclecloud.natgateway.createnatgateway com.oraclecloud.natgateway.deletenatgateway
    com.oraclecloud.natgateway.updatenatgateway com.oraclecloud.servicegateway.attachserviceid
    com.oraclecloud.servicegateway.changeservicegatewaycompartment
    com.oraclecloud.servicegateway.createservicegateway
    com.oraclecloud.servicegateway.deleteservicegateway.end
    com.oraclecloud.servicegateway.detachserviceid
    com.oraclecloud.servicegateway.updateservicegateway Verify the value of the is-enabled
    attribute is true In the JSON output verify that actionType is ONS and locate the topic-id
    Verify the correct topic is used by checking the topic name oci ons topic get --topic-id
    <topic-id> --query data.{"name:name"} --output table
  CHECK

  desc 'fix', <<~FIX
    From Console: Go to the Events Service page: https://cloud.oracle.com/events/rules Select

    the compartment that should host the rule Click Create Rule Provide a Display Name and
    Description Create a Rule Condition by selecting Networking in the Service Name Drop-down
    and selecting: DRG – Create DRG – Delete DRG – Update DRG Attachment – Create DRG
    Attachment – Delete DRG Attachment – Update Internet Gateway – Create Internet Gateway –
    Delete Internet Gateway – Update Internet Gateway – Change Compartment Local Peering
    Gateway – Create Local Peering Gateway – Delete End Local Peering Gateway – Update Local
    Peering Gateway – Change Compartment NAT Gateway – Create NAT Gateway – Delete NAT Gateway
    – Update NAT Gateway – Change Compartment Service Gateway – Create Service Gateway –
    Delete End Service Gateway – Update Service Gateway – Attach Service Service Gateway –
    Detach Service Service Gateway – Change Compartment In the Actions section select
    Notifications as Action Type Select the Compartment that hosts the Topic to be used.
    Select the Topic to be used Optionally add Tags to the Rule Click Create Rule From CLI:

    Find the topic-id of the topic the Event Rule should use for sending Notifications by
    using the topic name and Compartment OCID oci ons topic list --compartment-id
    <compartment-ocid> --all --query "data
    [?name=='<topic_name>']".{"name:name,topic_id:"topic-id""} --output table Create a JSON
    file to be used when creating the Event Rule. Replace topic id, display name, description
    and compartment OCID. { "actions": { "actions": [ { "actionType": "ONS", "isEnabled":

    true, "topicId": "<topic-id>" } ] }, "condition":

    "{"eventType":["com.oraclecloud.virtualnetwork.createdrg","com.oraclecloud.virtualnetwork.deletedrg","com.oraclecloud.virtualnetwork.updatedrg","com.oraclecloud.virtualnetwork.createdrgattachment","com.oraclecloud.virtualnetwork.deletedrgattachment","com.oraclecloud.virtualnetwork.updatedrgattachment","com.oraclecloud.virtualnetwork.changeinternetgatewaycompartment","com.oraclecloud.virtualnetwork.createinternetgateway","com.oraclecloud.virtualnetwork.deleteinternetgateway","com.oraclecloud.virtualnetwork.updateinternetgateway","com.oraclecloud.virtualnetwork.changelocalpeeringgatewaycompartment","com.oraclecloud.virtualnetwork.createlocalpeeringgateway","com.oraclecloud.virtualnetwork.deletelocalpeeringgateway.end","com.oraclecloud.virtualnetwork.updatelocalpeeringgateway","com.oraclecloud.natgateway.changenatgatewaycompartment","com.oraclecloud.natgateway.createnatgateway","com.oraclecloud.natgateway.deletenatgateway","com.oraclecloud.natgateway.updatenatgateway","com.oraclecloud.servicegateway.attachserviceid","com.oraclecloud.servicegateway.changeservicegatewaycompartment","com.oraclecloud.servicegateway.createservicegateway","com.oraclecloud.servicegateway.deleteservicegateway.end","com.oraclecloud.servicegateway.detachserviceid","com.oraclecloud.servicegateway.updateservicegateway"],"data":{}}",
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
  tag benchmark_ref: '4.12'
  tag cis_level: 'Level 1'
  tag assessment_status: 'Automated'
  tag cis_controls: %w[4.2]

  tag cci: %w[CCI-002323]

  tag nist: ['AC-18']

  required_event_types = [
    'com.oraclecloud.virtualnetwork.createdrg',
    'com.oraclecloud.virtualnetwork.deletedrg',
    'com.oraclecloud.virtualnetwork.updatedrg',
    'com.oraclecloud.virtualnetwork.createdrgattachment',
    'com.oraclecloud.virtualnetwork.deletedrgattachment',
    'com.oraclecloud.virtualnetwork.updatedrgattachment',
    'com.oraclecloud.virtualnetwork.changeinternetgatewaycompartment',
    'com.oraclecloud.virtualnetwork.createinternetgateway',
    'com.oraclecloud.virtualnetwork.deleteinternetgateway',
    'com.oraclecloud.virtualnetwork.updateinternetgateway',
    'com.oraclecloud.virtualnetwork.changelocalpeeringgatewaycompartment',
    'com.oraclecloud.virtualnetwork.createlocalpeeringgateway',
    'com.oraclecloud.virtualnetwork.deletelocalpeeringgateway.end',
    'com.oraclecloud.virtualnetwork.updatelocalpeeringgateway',
    'com.oraclecloud.natgateway.changenatgatewaycompartment',
    'com.oraclecloud.natgateway.createnatgateway',
    'com.oraclecloud.natgateway.deletenatgateway',
    'com.oraclecloud.natgateway.updatenatgateway',
    'com.oraclecloud.servicegateway.attachserviceid',
    'com.oraclecloud.servicegateway.changeservicegatewaycompartment',
    'com.oraclecloud.servicegateway.createservicegateway',
    'com.oraclecloud.servicegateway.deleteservicegateway.end',
    'com.oraclecloud.servicegateway.detachserviceid',
    'com.oraclecloud.servicegateway.updateservicegateway'
  ]

  tenancy_ocid = input('tenancy_ocid')
  topic_name = input('network_gateway_notification_topic')

  rules = oci_event_rules(compartment_id: tenancy_ocid)
  missing = rules.missing_regions(required_event_types: required_event_types, topic_name: topic_name)

  describe 'Network gateway change notifications' do
    it 'should have enabled event rules with an active ONS topic in all regions' do
      expect(missing).to be_empty,
                         "Regions missing compliant event rules: #{missing.join(', ')}"
    end
  end
end
