control "1_6" do
  title "Ensure IAM password policy prevents password reuse"
  desc "IAM password policies can prevent the reuse of a given password by the same user. It is recommended the password policy prevent the reuse of passwords.

Enforcing password history ensures that passwords are not reused in for a certain period of time by the same user. If a user is not allowed to use last 24 passwords, that window of time is greater. This helps maintain the effectiveness of password security."
  desc "check", "Go to Identity Domains: https://cloud.oracle.com/identity/domains/ Select the Compartment your Domain to review is in Click on the Domain to review Click on Settings Click on Password policy Click each Password policy in the domain Ensure Previous passwords remembered is set 24 or greater"
  desc "fix", "Go to Identity Domains: https://cloud.oracle.com/identity/domains/ Select the Compartment the Domain to remediate is in Click on the Domain to remediate Click on Settings Click on Password policy to remediate Click Edit password rules Update the number of remembered passwords in Previous passwords remembered setting to 24 or greater."
  desc "mitigations", "The Audit Procedure and Remediation Procedure for OCI IAM without Identity Domains can be found in the CIS OCI Foundation Benchmark 2.0.0 under the respective recommendations."
  impact 0.5
  tag check_id: "C-1_6"
  tag severity: "medium"
  tag gid: "CIS-1_6"
  tag rid: "xccdf_cis_cis_rule_1_6"
  tag stig_id: "1.6"
  tag gtitle: "<GroupDescription></GroupDescription>"
  tag "documentable"
  tag cci: ["CCI-001097", "CCI-001098", "CCI-002395", "CCI-000200", "CCI-000199", "CCI-000205", "CCI-000204"]
  tag nist: ["SC-7 a", "SC-7 c", "SC-7 b", "IA-5 (1) (e)", "IA-5 (1) (d)", "IA-5 (1) (a)", "IA-5 (8)"]
end
