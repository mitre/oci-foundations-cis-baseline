control "4_1" do
  title "Ensure default tags are used on resources"
  desc "Using default tags is a way to ensure all resources that support tags are tagged during creation. Tags can be based on static or computed values. It is recommended to set up default tags early after root compartment creation to ensure all created resources will get tagged.
Tags are scoped to Compartments and are inherited by Child Compartments. The recommendation is to create default tags like “CreatedBy” at the Root Compartment level to ensure all resources get tagged.
When using Tags it is important to ensure that Tag Namespaces are protected by IAM Policies otherwise this will allow users to change tags or tag values.
Depending on the age of the OCI Tenancy there may already be Tag defaults setup at the Root Level and no need for further action to implement this action.

In the case of an incident having default tags like “CreatedBy” applied will provide info on who created the resource without having to search the Audit logs."
  desc "check", %q(From Console: Login to OCI Console. From the navigation menu, select Identity & Security . Under Identity , select Compartments . Click the name of the root compartment. Under Resources , select Tag Defaults . In the Tag Defaults table, verify that there is a Tag with a value of ${iam.principal.name} and a Tag Key Status of Active . Note:
The name of the tag may be different then “CreatedBy” if the Tenancy Administrator has decided to use another tag. From CLI: List the active tag defaults defined at the Root compartment level by using the Tenancy OCID as compartment id.
Note: The Tenancy OCID can be found in the ~/.oci/config file used by the OCI Command Line Tool oci iam tag-default list --compartment-id=<tenancy_ocid> --query="data [?\"lifecycle-state\"=='ACTIVE']".{"name:\"tag-definition-name\","value:value""} --output table Verify in the table returned that there is at least one row that contains the value of ${iam.principal.name} .)
  desc "fix", 'From Console: Login to OCI Console. From the navigation menu, select Governance & Administration . Under Tenancy Management , select Tag Namespaces . Under Compartment , select the root compartment. If no tag namespace exists, click Create Tag Namespace , enter a name and description and click Create Tag Namespace . Click the name of a tag namespace. Click Create Tag Key Definition . Enter a tag key (e.g. CreatedBy) and description, and click Create Tag Key Definition . From the navigation menu, select Identity & Security . Under Identity , select Compartments . Click the name of the root compartment. Under Resources , select Tag Defaults . Click Create Tag Default . Select a tag namespace, tag key, and enter ${iam.principal.name} as the tag value. Click Create . From CLI: Create a Tag Namespace in the Root Compartment oci iam tag-namespace create --compartment-id=<tenancy_ocid> --name=<name> --description=<description> --query data.{"\\"Tag Namespace OCID\\":id"} --output table Note the Tag Namespace OCID and use it when creating the Tag Key Definition oci iam tag create --tag-namespace-id=<tag_namespace_ocid> --name=<tag_key_name> --description=<description> --query data.{"\\"Tag Key Definition OCID\\":id"} --output table Note the Tag Key Definition OCID and use it when creating the Tag Default in the Root compartment oci iam tag-default create --compartment-id=<tenancy_ocid> --tag-definition-id=<tag_key_definition_id> --value="\\${iam.principal.name}"'
  desc "mitigations", "There is no requirement to use the “Oracle-Tags” namespace to implement this control.
A Tag Namespace Administrator can create any namespace and use it for this control."
  desc "potential_impacts", "There is no performance impact when enabling the above described features."
  impact 0.5
  tag check_id: "C-4_1"
  tag severity: "medium"
  tag gid: "CIS-4_1"
  tag rid: "xccdf_cis_cis_rule_4_1"
  tag stig_id: "4.1"
  tag gtitle: "<GroupDescription></GroupDescription>"
  tag "documentable"
  tag cci: ["CCI-000389", "CCI-000395", "CCI-000399", "CCI-001780", "CCI-000389", "CCI-000395", "CCI-001780"]
  tag nist: ["CM-8 a 1", "CM-8 a 3", "CM-8 a 4", "CM-8 b", "CM-8 a 1", "CM-8 a 3", "CM-8 b"]
end
