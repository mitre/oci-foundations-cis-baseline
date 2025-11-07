control "1_16" do
  title "Ensure OCI IAM credentials unused for 45 days or more are disabled"
  desc "OCI IAM Local users can access OCI resources using different credentials, such as passwords or API keys. It is recommended that credentials that have been unused for 45 days or more be deactivated or removed.

Disabling or removing unnecessary OCI IAM local users will reduce the window of opportunity for credentials associated with a compromised or abandoned account to be used."
  desc "check", %q(Perform the following to determine if unused credentials exist: From Console: For Passwords: Login to OCI Console. Select Identity & Security from the Services menu. Select Domains from the Identity menu. For each domain listed, click on the name Click Reports Under Dormant users report click View report Enter a date 45 days from today’s date in Last Successful Login Date Check and ensure that Last Successful Login Date is greater than 45 days or empty For API Keys: Login to OCI Console. Select Observability & Management from the Services menu. Select Search from Logging menu Click Show Advanced Mode in the right corner Select Custom from Filter by time Under Select regions to search add regions Under Query enter the following query in the text box: search "<tenancy-ocid>/_Audit_Include_Subcompartment" | data.identity.credentials='<tenancy-ocid>/<user-ocid>/<key-fingerprint>'  | summarize count() by data.identity.principalId Enter a day range Note each query can only be 14 days multiple queries will be required to go 45 days Click Search Expand the results If results the count is not zero the user has used their API key during that period Repeat steps 8 – 11 for the 45-day period From CLI: For Passwords: Execute the below: oci identity-domains users list --all --endpoint <identity-domain-endpoint> --attributes urn:ietf:params:scim:schemas:oracle:idcs:extension:userState:User:lastSuccessfulLoginDate --profile Oracle --query '.data.resources[]|."user-name" + "  " + ."urn-ietf-params-scim-schemas-oracle-idcs-extension-user-state-user"."last-successful-login-date"' Review the output the that the date is under 45 days, or no date means they have not logged in For API Keys: Create the search query text: export query="search \"<tenancy-ocid>/_Audit_Include_Subcompartment\" | data.identity.credentials='*<key-finger-print>'  | summarize count() by data.identity.principalId" Select a day range. Date format is 2024-12-01 Note each query can only be 14 days multiple queries will be required to go 45 days Execute the below: oci logging-search search-logs --search-query $query --time-start <start-date> --time-end <end-date> --query 'data.results[0].data.count' 
export query="search \"<tenancy-ocid>/_Audit_Include_Subcompartment\" | data.identity.credentials='*<key-finger-print>'  | summarize count() by data.identity.principalId" If results the count is not zero, the user has used their API key during that period Repeat steps 2 – 4 for the 45-day period)
  desc "fix", 'From Console: Login to OCI Console. Select Identity & Security from the Services menu. Select Domains from the Identity menu. For each domain listed, click on the name and select Users . Click on an individual user under the Username heading. Click More action Select Deactivate From CLI: Create a input.json: {
    "operations": [
      { "op": "replace", "path": "active","value": false}
    ],
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "userId": "<user-ocid>"
  } Execute the below: oci identity-domains user patch --from-json file://file.json --endpoint <identity-domain-endpoint>'
  desc "mitigations", "This audit should exclude the OCI Administrator, break-glass accounts, and service accounts as these accounts should only be used for day-to-day business and would likely be unused for up to 45 days."
  impact 0.5
  tag check_id: "C-1_16"
  tag severity: "medium"
  tag gid: "CIS-1_16"
  tag rid: "xccdf_cis_cis_rule_1_16"
  tag stig_id: "1.16"
  tag gtitle: "<GroupDescription></GroupDescription>"
  tag "documentable"
  tag cci: ["CCI-000011", "CCI-002121", "CCI-000012", "CCI-002122", "CCI-000664"]
  tag nist: ["AC-2 f", "AC-2 f", "AC-2 j", "AC-2 g", "SA-8"]
end
