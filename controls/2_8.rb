control '2_8' do
  title 'Ensure Oracle Autonomous Shared Databases (ADB) access is restricted to allowed sources or deployed within a Virtual Cloud Network'
  desc 'Oracle Autonomous Database Shared (ADB-S) automates database tuning, security, backups, updates, and other routine management tasks traditionally performed by DBAs. ADB-S provide ingress filtering of network traffic or can be deployed within an existing Virtual Cloud Network (VCN).  It is recommended that all new ADB-S databases be deployed within a VCN and that the Access Control Rules are restricted to your corporate IP Addresses or VCNs for existing ADB-S databases.

Restricting connectivity to ADB-S Databases reduces an ADB-S database’s exposure to risk.'
  desc 'check', %q(From Console: Login into the OCI Console Click in the search bar, top of the screen. Type Advanced Resource Query and hit enter. Click the Advanced Resource Query button in the upper right of the screen. Enter the following query in the query box: query autonomousdatabase resources For each ABD-S database returned click on the link under Display name Click Edit next to Access Control List Ensure `Access Control Rules’  IP Address/CIDR Block as well as VCNs are correct Repeat for other subscribed regions From CLI: Execute the following command: for region in `oci iam region list | jq -r '.data[] | .name'`;
   do
       for compid in `oci iam compartment list --compartment-id-in-subtree TRUE 2>/dev/null | jq -r '.data[] | .id'`
        do
            for adbid in `oci db autonomous-database list --compartment-id $compid --region $region --all 2>/dev/null | jq -r '.data[] | select(."nsg-ids"  == null).id'`
                do
                output=`oci db autonomous-database get --autonomous-database-id $adbid --region $region --query=data.{"WhiteListIPs:\"whitelisted-ips\","id:id""} --output table 2>/dev/null`
                if [ ! -z "$output" ]; then echo $output; fi
                done
        done
   done Ensure WhiteListIPs are correct.)
  desc 'fix', "From Console: Follow the audit procedure above. For each ADB-S database in the returned results, click the ADB-S database name Click Edit next to Access Control Rules Click +Another Rule and add rules as required Click Save Changes From CLI: Follow the audit procedure. Get the json input format by executing the following command: oci db autonomous-database update --generate-full-command-json-input For each of the ADB-S Database identified get its details. Update the whitelistIps , copy the WhiteListIPs element from the JSON returned by the above get call, edit it appropriately and use it in the following command: oci db autonomous-database update –-autonomous-database-id <ABD-S OCID> --from-json '<network endpoints JSON>'"
  desc 'potential_impacts', 'When updating ingress filters for an existing environment, care should be taken to ensure that IP addresses and VCNs currently used by administrators, users, and services to access your ADB-S instances are included in the updated filters.'
  impact 0.5
  tag check_id: 'C-2_8'
  tag severity: 'medium'
  tag gid: 'CIS-2_8'
  tag rid: 'xccdf_cis_cis_rule_2_8'
  tag stig_id: '2.8'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag 'documentable'
  tag cci: ['CCI-001097', 'CCI-001098', 'CCI-002395', 'CCI-002668', 'CCI-002669', 'CCI-001243', 'CCI-001184', 'CCI-000364', 'CCI-000366', 'CCI-000381']
  tag nist: ['SC-7 a', 'SC-7 c', 'SC-7 b', 'SI-4 (11)', 'SI-4 (13) (c)', 'SI-3 c 2', 'SC-23', 'CM-6 a', 'CM-6 b', 'CM-7 a']
end
