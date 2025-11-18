# Control 1_5: CLI/API Implementation Guide

## Check Requirement Summary

**Control:** Ensure IAM password policy expires passwords within 365 days

**Current Manual Check Process:**
1. Go to Identity Domains: https://cloud.oracle.com/identity/domains/
2. Select the compartment containing the Domain to review
3. Click on the Domain to review
4. Navigate to: Settings → Password policy
5. For each password policy in the domain, verify "Expires after (days)" is set to 365 or fewer days

**Validation Criteria:**
- All password policies in a domain must have `expiresAfter` ≤ 365 days
- If no password policy exists, this may be a passing or failing condition depending on policy

---

## OCI CLI Implementation

### Prerequisites
- OCI CLI installed and configured with appropriate credentials
- Access to Identity Domains service
- Endpoint URL for the Identity Domain (required parameter)

### Key Command

```bash
oci identity-domains password-policies list --endpoint <DOMAIN_ENDPOINT> --all --output json
```

### Required Parameters

- `--endpoint`: The Identity Domain endpoint URL (required)
  - Format: `https://<domain-name>.identity.oraclecloud.com`
  - Must be obtained from the Identity Domain details

### Optional Parameters for Filtering

```bash
# List all password policies with pagination
oci identity-domains password-policies list \
  --endpoint <DOMAIN_ENDPOINT> \
  --all \
  --output json

# Filter by specific attributes
oci identity-domains password-policies list \
  --endpoint <DOMAIN_ENDPOINT> \
  --attributes "displayName,expiresAfter" \
  --output json

# With custom pagination
oci identity-domains password-policies list \
  --endpoint <DOMAIN_ENDPOINT> \
  --count 100 \
  --output json
```

### Example Response Structure

```json
{
  "data": {
    "Resources": [
      {
        "id": "password-policy-id-123",
        "schemas": [
          "urn:ietf:params:scim:schemas:oracle:idcs:PasswordPolicy"
        ],
        "meta": {
          "resourceType": "PasswordPolicy",
          "created": "2023-01-15T10:30:00Z",
          "lastModified": "2023-06-20T14:15:00Z"
        },
        "displayName": "Default Password Policy",
        "expiresAfter": 365,
        "minLength": 12,
        "maxLength": 256,
        "minAlphabeticCharacters": 1,
        "minNumericCharacters": 1,
        "minSpecialCharacters": 1,
        "maxRepeatedCharacters": 3,
        "minUniqueCharacters": 3,
        "passwordStrengthRequired": true,
        "notContainDisplayName": true,
        "notContainUserName": true
      },
      {
        "id": "password-policy-id-456",
        "displayName": "Strict Password Policy",
        "expiresAfter": 180,
        "minLength": 16
      }
    ],
    "totalResults": 2,
    "itemsPerPage": 100,
    "startIndex": 1
  }
}
```

### Key Response Fields

- **`expiresAfter`**: Number of days before a password expires (target field for validation)
- **`displayName`**: User-friendly name of the password policy
- **`minLength`**: Minimum password length
- **`maxLength`**: Maximum password length
- **`minNumericCharacters`**: Required numeric characters
- **`minSpecialCharacters`**: Required special characters
- **`passwordStrengthRequired`**: Whether password strength is enforced

---

## OCI REST API Implementation

### Endpoint

```
GET /admin/v1/PasswordPolicies
```

### Base URL

```
https://<domain-name>.identity.oraclecloud.com
```

### Authentication

All requests require OCI signature-based authentication using:
- Authorization header with signature
- Standard OCI authentication headers

### Request Example

```bash
curl -X GET \
  'https://<domain-name>.identity.oraclecloud.com/admin/v1/PasswordPolicies' \
  -H 'Authorization: <OCI_SIGNATURE>' \
  -H 'Content-Type: application/json'
```

### Query Parameters

| Parameter | Type | Optional | Description |
|-----------|------|----------|-------------|
| `filter` | string | Yes | SCIM filter expression (e.g., `filter=expiresAfter le 365`) |
| `sortBy` | string | Yes | Attribute to sort by |
| `sortOrder` | string | Yes | `ASCENDING` or `DESCENDING` |
| `startIndex` | integer | Yes | 1-based pagination start index |
| `count` | integer | Yes | Maximum results per page (max 1000) |
| `attributes` | string | Yes | Comma-separated attribute names to return |

### Example API Request with Filter

```bash
GET /admin/v1/PasswordPolicies?filter=expiresAfter%20le%20365&count=100
```

### Response Schema

```json
{
  "schemas": [
    "urn:ietf:params:scim:api:messages:2.0:ListResponse"
  ],
  "totalResults": 2,
  "itemsPerPage": 100,
  "startIndex": 1,
  "Resources": [
    {
      "id": "password-policy-id-123",
      "schemas": [
        "urn:ietf:params:scim:schemas:oracle:idcs:PasswordPolicy"
      ],
      "meta": {
        "resourceType": "PasswordPolicy",
        "created": "2023-01-15T10:30:00Z",
        "lastModified": "2023-06-20T14:15:00Z",
        "location": "https://<domain-name>.identity.oraclecloud.com/admin/v1/PasswordPolicies/password-policy-id-123"
      },
      "displayName": "Default Password Policy",
      "expiresAfter": 365,
      "minLength": 12,
      "maxLength": 256,
      "minAlphabeticCharacters": 1,
      "minNumericCharacters": 1,
      "minSpecialCharacters": 1,
      "maxRepeatedCharacters": 3,
      "minUniqueCharacters": 3,
      "passwordStrengthRequired": true,
      "notContainDisplayName": true,
      "notContainUserName": true
    }
  ]
}
```

---

## InSpec Control Implementation Strategy

### Approach

1. **Retrieve all Identity Domains** in the target compartment
2. **For each Identity Domain**, get its endpoint URL
3. **Query password policies** via CLI or API
4. **Validate** that all password policies have `expiresAfter` ≤ 365 days

### Pseudo-Code Structure

```ruby
control '1_5' do
  title 'Ensure IAM password policy expires passwords within 365 days'
  
  # Get all Identity Domains in compartment
  domains = fetch_identity_domains(compartment_id)
  
  domains.each do |domain|
    domain_endpoint = domain['url']  # e.g., https://example.identity.oraclecloud.com
    
    # Query password policies for this domain
    policies = oci_cli_exec([
      'oci', 'identity-domains', 'password-policies', 'list',
      '--endpoint', domain_endpoint,
      '--all',
      '--output', 'json'
    ])
    
    policies_data = JSON.parse(policies)
    
    # Validate each policy
    policies_data['data']['Resources'].each do |policy|
      describe "Password policy '#{policy['displayName']}' in domain '#{domain['name']}'" do
        subject { policy['expiresAfter'] }
        it { should be <= 365 }
      end
    end
  end
end
```

### Required InSpec Resources

You may need to:
1. Create a custom InSpec resource for querying OCI CLI
2. Use the existing `command` resource to execute OCI CLI
3. Parse JSON output for validation

### Example InSpec Implementation

```ruby
control '1_5' do
  title 'Ensure IAM password policy expires passwords within 365 days'
  
  impact 0.5
  
  # Assuming you have a helper to get domains and endpoint
  domains_endpoint = ENV['OCI_DOMAIN_ENDPOINT'] # Must be provided
  
  describe 'Password policy expiration' do
    skip 'Requires OCI_DOMAIN_ENDPOINT environment variable' unless domains_endpoint
    
    subject {
      json_command = command("oci identity-domains password-policies list --endpoint #{domains_endpoint} --all --output json")
      JSON.parse(json_command.stdout)
    }
    
    it 'should have all password policies with expiresAfter <= 365 days' do
      resources = subject.dig('data', 'Resources') || []
      
      resources.each do |policy|
        expect(policy['expiresAfter']).to be <= 365, 
          "Policy '#{policy['displayName']}' has expiresAfter=#{policy['expiresAfter']} > 365"
      end
    end
  end
end
```

---

## Required Information for Implementation

To implement automated validation via CLI/API, you will need:

1. **Domain Endpoint URL**
   - Obtained from Identity Domain details in OCI console
   - Format: `https://<domain-name>.identity.oraclecloud.com`

2. **OCI CLI Credentials**
   - ~/.oci/config with appropriate user credentials
   - Permissions to read Identity Domain password policies

3. **Compartment Information**
   - Compartment ID/OCID where Identity Domains are located

4. **Authentication Method**
   - OCI API signature authentication for REST API calls
   - Or CLI with pre-configured credentials

---

## Testing Commands

### List all password policies (CLI)

```bash
oci identity-domains password-policies list \
  --endpoint https://example.identity.oraclecloud.com \
  --all \
  --output json | jq '.data.Resources[] | {displayName, expiresAfter}'
```

### Get a specific password policy

```bash
oci identity-domains password-policy get \
  --endpoint https://example.identity.oraclecloud.com \
  --password-policy-id password-policy-id-123 \
  --output json
```

### Filter policies with jq

```bash
oci identity-domains password-policies list \
  --endpoint https://example.identity.oraclecloud.com \
  --all \
  --output json | jq '.data.Resources[] | select(.expiresAfter > 365) | {displayName, expiresAfter}'
```

---

## References

- [OCI Identity Domains - Password Policies API](https://docs.oracle.com/en-us/iaas/api/#/en/identity-domains/latest/PasswordPolicy/)
- [OCI CLI - Identity Domains Commands](https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/identity-domains.html#identity-domains-password-policies)
- [SCIM Protocol - Filtering, Sorting, and Pagination](https://tools.ietf.org/html/rfc7644#section-3.4.2)

