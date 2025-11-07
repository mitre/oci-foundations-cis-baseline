control "2_6" do
  title "Ensure Oracle Integration Cloud (OIC) access is restricted to allowed sources."
  desc "Oracle Integration (OIC) is a complete, secure, but lightweight integration solution that enables you to connect your applications in the cloud. It simplifies connectivity between your applications and connects both your applications that live in the cloud and your applications that still live on premises. Oracle Integration provides secure, enterprise-grade connectivity regardless of the applications you are connecting or where they reside. OIC instances are created within an Oracle managed secure private network with each having a public endpoint. The capability to configure ingress filtering of network traffic to protect your OIC instances from unauthorized network access is included. It is recommended that network access to your OIC instances be restricted to your approved corporate IP Addresses or Virtual Cloud Networks (VCN)s.

Restricting connectivity to OIC Instances reduces an OIC instance’s exposure to risk."
  desc "check", %q(From Console: Login into the OCI Console Click in the search bar, top of the screen. Type Advanced Resource Query and hit enter. Click the Advanced Resource Query button in the upper right of the screen. Enter the following query in the query box: query integrationinstance resources For each OIC Instance returned click on the link under Display name Click on Network Access 8 .Ensure Restrict Network Access is selected and the IP Address/CIDR Block as well as Virtual Cloud Networks are correct Repeat for other subscribed regions From CLI: Execute the following command: for region in `oci iam region list | jq -r '.data[] | .name'`;
   do
       for compid in `oci iam compartment list --compartment-id-in-subtree TRUE 2>/dev/null | jq -r '.data[] | .id'`
        do
            output=`oci integration integration-instance list --compartment-id $compid --region $region --all 2>/dev/null | jq -r '.data[] | select(."network-endpoint-details"."network-endpoint-type" == null)'`
            if [ ! -z "$output" ]; then echo $output; fi
        done
   done Ensure allowlisted-http-ips and allowed-http-vcns are correct)
  desc "fix", "From Console: Follow the audit procedure above. For each OIC instance in the returned results, click the OIC Instance name Click Network Access Either edit the Network Access to be more restrictive From CLI Follow the audit procedure. Get the json input format using the below command: oci integration integration-instance change-network-endpoint --generate-param-json-input 3.For each of the OIC Instances identified get its details.
4.Update the Network Access , copy the network-endpoint-details element from the JSON returned by the above get call, edit it appropriately and use it in the following command Oci integration integration-instance change-network-endpoint --id <oic-instance-id> --from-json '<network endpoints JSON>'"
  desc "potential_impacts", "When updating ingress filters for an existing environment, care should be taken to ensure that IP addresses and VCNs currently used by administrators, users, and services to access your OIC instances are included in the updated filters."
  impact 0.5
  tag check_id: "C-2_6"
  tag severity: "medium"
  tag gid: "CIS-2_6"
  tag rid: "xccdf_cis_cis_rule_2_6"
  tag stig_id: "2.6"
  tag gtitle: "<GroupDescription></GroupDescription>"
  tag "documentable"
  tag cci: ["CCI-001097", "CCI-001098", "CCI-002395", "CCI-002668", "CCI-002669", "CCI-001243", "CCI-001184", "CCI-000364", "CCI-000366", "CCI-000381"]
  tag nist: ["SC-7 a", "SC-7 c", "SC-7 b", "SI-4 (11)", "SI-4 (13) (c)", "SI-3 c 2", "SC-23", "CM-6 a", "CM-6 b", "CM-7 a"]
end
