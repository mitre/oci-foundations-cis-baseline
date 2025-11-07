control "5_1_3" do
  title "Ensure Versioning is Enabled for Object Storage Buckets"
  desc "A bucket is a logical container for storing objects. Object versioning is enabled at the bucket level and is disabled by default upon creation.  Versioning directs Object Storage to automatically create an object version each time a new object is uploaded, an existing object is overwritten, or when an object is deleted. You can enable object versioning at bucket creation time or later.

Versioning object storage buckets provides for additional integrity of your data. Management of data integrity is critical to protecting and accessing protected data. Some customers want to identify object storage buckets without versioning in order to apply their own data lifecycle protection and management policy."
  desc "check", %q(From Console: Login to OCI Console. Select Storage from the Services menu. Select Buckets from under the Object Storage & Archive Storage section. Click on an individual bucket under the Name heading. Ensure that the Object Versioning is set to Enabled. Repeat for each compartment From CLI: Execute the following command: for region in $(oci iam region-subscription list --all | jq -r '.data[] | ."region-name"')
do
  echo "Enumerating region $region"
  for compid in $(oci iam compartment list --include-root --compartment-id-in-subtree TRUE 2>/dev/null | jq -r '.data[] | .id')
  do
    echo "Enumerating compartment $compid"
    for bkt in $(oci os bucket list --compartment-id $compid --region $region 2>/dev/null | jq -r '.data[] | .name')
    do
      output=$(oci os bucket get --bucket-name $bkt --region $region 2>/dev/null | jq -r '.data | select(."versioning" == "Disabled").name')
      if [ ! -z "$output" ]; then echo $output; fi
    done
  done
done Ensure no results are returned.)
  desc "fix", "From Console: Follow the audit procedure above. For each bucket in the returned results, click the Bucket Display Name Click Edit next to Object Versioning: Disabled Click Enable Versioning From CLI: Follow the audit procedure For each of the buckets identified, execute the following command: oci os bucket update --bucket-name <bucket name> --versioning Enabled"
  impact 0.5
  tag check_id: "C-5_1_3"
  tag severity: "medium"
  tag gid: "CIS-5_1_3"
  tag rid: "xccdf_cis_cis_rule_5_1_3"
  tag stig_id: "5.1.3"
  tag gtitle: "<GroupDescription></GroupDescription>"
  tag "documentable"
end
