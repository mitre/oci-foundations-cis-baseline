control "4_16" do
  title "Ensure customer created Customer Managed Key (CMK) is rotated at least annually"
  desc "Oracle Cloud Infrastructure Vault securely stores master encryption keys that protect your encrypted data. You can use the Vault service to rotate keys to generate new cryptographic material. Periodically rotating keys limits the amount of data encrypted by one key version.

Rotating keys annually limits the data encrypted under one key version. Key rotation thereby reduces the risk in case a key is ever compromised."
  desc "check", %q(From Console: Login into OCI Console. Select Identity & Security from the Services menu. Select Vault . Click on the individual Vault under the Name heading. Ensure the date of each Master Encryption key under the Created column of the Master Encryption key is no more than 365 days old, and that the key is in the ENABLED state Repeat for all Vaults in all compartments From CLI: Execute the following for each Vault in each compartment oci kms management key list --compartment-id '<compartment-id>' --endpoint '<management-endpoint-url>' --all --query "data[*].[\"time-created\",\"display-name\",\"lifecycle-state\"]" Ensure the date of the Master Encryption key is no more than 365 days old and is also in the ENABLED state.)
  desc "fix", "From Console: Login into OCI Console. Select Identity & Security from the Services menu. Select Vault . Click on the individual Vault under the Name heading. Click on the menu next to the time created. Click Rotate Key From CLI: Execute the following: oci kms management key rotate --key-id <key-ocid> --endpoint <management-endpoint-url>"
  impact 0.5
  tag check_id: "C-4_16"
  tag severity: "medium"
  tag gid: "CIS-4_16"
  tag rid: "xccdf_cis_cis_rule_4_16"
  tag stig_id: "4.16"
  tag gtitle: "<GroupDescription></GroupDescription>"
  tag "documentable"
end
