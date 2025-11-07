control "1_7" do
  title "Ensure MFA is enabled for all users with a console password"
  desc "Multi-factor authentication is a method of authentication that requires the use of more than one factor to verify a user’s identity. With MFA enabled in the IAM service, when a user signs in to Oracle Cloud Infrastructure, they are prompted for their user name and password, which is the first factor (something that they know). The user is then prompted to provide a verification code from a registered MFA device, which is the second factor (something that they have). The two factors work together, requiring an extra layer of security to verify the user’s identity and complete the sign-in process. OCI IAM supports two-factor authentication using a password (first factor) and a device that can generate a time-based one-time password (TOTP) (second factor). See OCI documentation for more details.

Multi factor authentication adds an extra layer of security during the login process and makes it harder for unauthorized users to gain access to OCI resources."
  desc "check", %q(From Console: Go to Identity Domains: https://cloud.oracle.com/identity/domains/ Select the Compartment your Domain to review is in Click on the Domain to review Click on Security Click Sign-on policies Select the sign-on policy to review Under the sign-on rules header, click the three dots on the rule with the highest priority. Select Edit sign-on rule Verify that allow access is selected and prompt for an additional factor is enabled This requires users to enable MFA when they next login next however, to determine users have enabled MFA use the below CLI. From the CLI: This CLI command checks which users have enabled MFA for their accounts Execute the below: tenancy_ocid=`oci iam compartment list --raw-output --query "data[?contains(\"compartment-id\",'.tenancy.')].\"compartment-id\" | [0]"`
for id_domain_url in `oci iam domain list --compartment-id $tenancy_ocid --all | jq -r '.data[] | .url'`
do
    oci identity-domains users list --endpoint $id_domain_url 2>/dev/null | jq -r '.data.resources[] | select(."urn-ietf-params-scim-schemas-oracle-idcs-extension-mfa-user"."mfa-status"!="ENROLLED")' 2>/dev/null | jq -r '.ocid'
    
done
for region in `oci iam region-subscription list | jq -r '.data[] | ."region-name"'`;
   do
       for compid in `oci iam compartment list --compartment-id-in-subtree TRUE --all 2>/dev/null | jq -r '.data[] | .id'`
        do
            for id_domain_url in `oci iam domain list --compartment-id $compid --region $region --all 2>/dev/null | jq -r '.data[] | .url'`
            do
                oci identity-domains users list --endpoint $id_domain_url 2>/dev/null | jq -r '.data.resources[] | select(."urn-ietf-params-scim-schemas-oracle-idcs-extension-mfa-user"."mfa-status"!="ENROLLED")' 2>/dev/null | jq -r '.ocid'
            done
        done
   done Ensure no results are returned)
  desc "fix", 'Each user must enable MFA for themselves using a device they will have access to every time they sign in. An administrator cannot enable MFA for another user but can enforce MFA by identifying the list of non-complaint users, notifying them or disabling access by resetting the password for non-complaint accounts. Disabling access from Console: Go to https://cloud.oracle.com/identity/ . Select Domains from Identity menu. Select the domain Click Security Click Sign-on polices then the "Default Sign-on Policy" Under the sign-on rules header, click the three dots on the rule with the highest priority. Select Edit sign-on rule Make a change to ensure that allow access is selected and prompt for an additional factor is enabled'
  desc "mitigations", "The Audit Procedure and Remediation Procedure for OCI IAM without Identity Domains can be found in the CIS OCI Foundation Benchmark 2.0.0 under the respective recommendations."
  impact 0.5
  tag check_id: "C-1_7"
  tag severity: "medium"
  tag gid: "CIS-1_7"
  tag rid: "xccdf_cis_cis_rule_1_7"
  tag stig_id: "1.7"
  tag gtitle: "<GroupDescription></GroupDescription>"
  tag "documentable"
  tag cci: ["CCI-001097", "CCI-001098", "CCI-002395", "CCI-000766", "CCI-001942", "CCI-001643", "CCI-001682", "CCI-000766", "CCI-001682", "CCI-001643", "CCI-001954", "CCI-001225", "CCI-001226", "CCI-001227", "CCI-001230"]
  tag nist: ["SC-7 a", "SC-7 c", "SC-7 b", "IA-2 (2)", "IA-2 (9)", "RA-5 a", "AC-2 (2)", "IA-2 (2)", "AC-2 (2)", "RA-5 a", "IA-2 (12)", "SI-2 a", "SI-2 a", "SI-2 a", "SI-2 d"]
end
