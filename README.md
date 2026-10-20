# Keycloak PII Data Encryption Provider

## Introduction

This provider encrypts user fields & attribute values before storing them to the database and decrypt them upon loading from the database. This is to address data security regulations such as GDPR that require any PII data to not be stored in plain/raw format at rest.

***Important: this provider supports Keycloak version 24.x and above only.*** 

## How to install

### Manual install

Git clone this repo:

```shell
git clone https://github.com/MLukman/Keycloak-PII-Data-Encryption-Provider.git Keycloak-PII-Data-Encryption-Provider
cd Keycloak-PII-Data-Encryption-Provider
```

Compile this provider into a JAR file using the following command. JDK 17 or above and Maven are required to be pre-installed on the machine. Make sure to match the `keycloak.version` parameter with the version of the target Keycloak.

```shell 
mvn clean package -Dkeycloak.version=26.3.0
```

Copy paste the packaged JAR file from inside `target` folder into Keycloak `providers` folder. Run `kc.sh build` command to get Keycloak to register this provider.

### Install inside Docker Image

Use this method if this provider needs to be pre-packaged inside a custom Keycloak Docker image. Below is a sample Dockerfile:

```dockerfile
# ARG defined before FROM in multi-staged Dockerfile is shared among the stages
ARG KEYCLOAK_VERSION=26.3.0

# Build the provider
FROM maven:3.8.1-openjdk-17-slim AS keycloak-pii-data-encryption
ARG KEYCLOAK_VERSION # Dockerfile peculiarity that requires ARG defined before FROM to be re-declared afterwards if we want to use it in the stage
WORKDIR /app
RUN apt-get update && apt-get install -y git && apt-get clean
RUN git clone https://github.com/MLukman/Keycloak-PII-Data-Encryption-Provider.git .
RUN mvn clean package -Dkeycloak.version=$KEYCLOAK_VERSION

################################################################################

# Base image from official keycloak
FROM quay.io/keycloak/keycloak:$KEYCLOAK_VERSION

# Add provider JAR
COPY --from=keycloak-pii-data-encryption /app/target/*.jar /opt/keycloak/providers

# Need to build after adding providers
RUN /opt/keycloak/bin/kc.sh build --db=mysql --features="declarative-ui" --spi-user-provider=jpa-encrypted

```

## How to use

### Configuring the encryption keys

Encryption is **envelope encryption**: every value is encrypted with its own random
data key (DEK), and that data key is wrapped (encrypted) by a master key (KEK).
Values are encrypted with AES-256-GCM, so the ciphertext is authenticated and
bound to the user and field it belongs to through AAD (additional authenticated
data). A keyed HMAC-SHA256 hash (blind index) is stored in place of each encrypted
field so exact-match searches and the uniqueness checks still work.

All keys are **versioned**. A key configuration is a comma-separated keyring in
the format `v1:<key>,v2:<key>`, where each entry is prefixed with its version. New
values always use the active version while older versions keep decrypting old
data, so a key can be rotated without losing access to anything.

| Environment variable | Purpose | Default |
| --- | --- | --- |
| `KC_PII_ENCKEY` | Master keys (KEK), e.g. `v1:<base64 key>` | MD5 hash of the database JDBC URL (see below) |
| `KC_PII_ENCKEY_ACTIVE` | Master key version used for new data keys | last entry of `KC_PII_ENCKEY` |
| `KC_PII_INDEXKEY` | Peppers for the blind index, same format | derived from the first master key |
| `KC_PII_INDEXKEY_ACTIVE` | Pepper version used for new blind indexes | last entry of `KC_PII_INDEXKEY` |
| `KC_PII_COUNTRY_CODE` | Country calling code used to normalize phone numbers for the blind index | `62` |

Each key must be 16, 24 or 32 bytes. **32 bytes (AES-256) is recommended**, and
keys can be generated with `openssl rand -base64 32`. Example:

```shell
export KC_PII_ENCKEY="v1:$(openssl rand -base64 32)"
export KC_PII_INDEXKEY="v1:$(openssl rand -base64 32)"
```

If `KC_PII_ENCKEY` is not provided, there is a default fallback that uses the MD5
hash of the database JDBC URL, either using configuration parameter `db-url` or
environment variable `KC_DB_URL`. If you rely on this fallback and in the future
need to migrate your Keycloak data into another database that results in a
different JDBC URL, you need to get the old value of the JDBC URL, encode it using
lowercased MD5 hash and set the value to the `KC_PII_ENCKEY` environment variable.

If `KC_PII_INDEXKEY` is not set, the blind index pepper is derived from the first
(oldest) master key so that a deployment only needs one variable. Set it
explicitly to keep the pepper independent from the master keys.

#### Upgrading from version 1.x

Version 1.x encrypted values directly with `KC_PII_ENCKEY` and hashed the search
columns with plain SHA-1. Both are still supported:

- A key without a version prefix (e.g. `KC_PII_ENCKEY=1234567891123456`) is
treated as the legacy key version `v0` and is still able to decrypt old values.
- Old values are decrypted with the legacy algorithm and re-encrypted in the new
  format the next time the user or attribute is written.
- Old 40-character SHA-1 hashes are still recognised by lookups and decryption
  verification until the rows are rewritten.

#### Key rotation

**Master key (KEK) rotation is cheap**: add a new key and mark it active, then
re-wrap the data keys. The PII ciphertext is not touched.

```shell
# 1. add the new key (v1 stays so old values keep decrypting) and restart
export KC_PII_ENCKEY="v1:<old key>,v2:<new key>"
export KC_PII_ENCKEY_ACTIVE="v2"
```

```java
// 2. per row: re-wrap the data key only (the ciphertext stays untouched), e.g.
// from a maintenance script that reads USER_ENTITY_ENCRYPTED / USER_ATTRIBUTE_ENCRYPTED
PiiCipher cipher = PiiCipher.getInstance();
String stored = row.getEmail();                                      // $$$v1:v1:<wrapped DEK>:<ciphertext>
String rewrapped = cipher.rewrapDataKey(ProtectedValue.parse(stored)).serialize();
// UPDATE USER_ENTITY_ENCRYPTED SET EMAIL = :rewrapped WHERE ID = :id
// rows already wrapped with the active key are returned unchanged by rewrapDataKey()
```

3. once no row references `v1` anymore, remove it from `KC_PII_ENCKEY`.

A data key (DEK) rotation re-encrypts the value itself:

```java
ProtectedValue rotated = cipher.rotateDataKey(value, aad);   // new DEK, new ciphertext
```

The blind index is not affected by either rotation. Rotating the pepper is a
plain re-index from the decrypted values: add the new pepper to
`KC_PII_INDEXKEY`, make it active, and rewrite the hash columns with
`LogicUtils.hash(...)` until no `v1:` hashes remain.

> Removing a master key (or pepper) from the keyring makes every value that still
> references it permanently unreadable. That is also how crypto-shredding works:
> drop the key to irreversibly destroy the data.

### Enabling 'declarative-ui' feature

This provider requires the Keycloak instance to be either built or started with the following flag:

-  `--features="declarative-ui"`

The flag can be added to the `build` command with a condition that the `start` command has the `--optimized` flag, or for `start` without that flag or `start-dev` command, the flag is to be added to the `start` or `start-dev` commands.

Note: the "declarative-ui" flag is only necessary while the feature is still considered experimental. Once it is enabled by default in future Keycloak versions, the flag will no longer be necessary.

### Adding the pre-requisite event listener

The encryption needs to be enabled realm-by-realm. Firstly, this provider requires enabling an event listener for the particular realms that require data encryption. Go to the `Realm settings` page and navigate to the `Events` tab. Add the event listener `pii-data-encryption`, as shown below: 

![Screenshot for adding event listener](docs/screenshot-add-event-listener.png)

### Enabling the encryption

To actually enable the encryption of the common user attributes `username`, `email`, `first name` and `last name` for users in a particular realm, go to the `Realm settings` page and navigate to the custom tab `User Entity Encryption`. Turn on the `Enable encryption` switch on that tab, as shown below:

![Screenshot of "User Entity Encryption" tab](docs/screenshot-enable-user-entity-encryption.png)

### Extending the encryption to custom attributes

To enable encryption of any custom attributes, go to the `User profile` tab and click on the specific attributes and add the custom validator of type `pii-data-encryption` under the `Validations` section.

![Screenshot of "Add validator" popup dialog](docs/screenshot-add-validator.png)

This provider also automatically encrypts any user attributes that have their names start with "pii-" prefix even without the validator.

### Verifying if the profile data are really encrypted (also explanations on how the encryptions work)

1. Browse the Keycloak database using any tool (e.g. phpMyAdmin for MySQL database).
2. Navigate to the table `USER_ENTITY`. Verify that the columns `USERNAME`, `EMAIL`, `FIRST_NAME` and `LAST_NAME` for the rows corresponding to users that have the encryption enabled will contain versioned HMAC-SHA256 blind index values in the format `v1:<64 hex characters>`, e.g. `v1:6ea7bdc669b8926a75fe165989270ed025ac94dd45c571a156ddcef41351a713`. Those hashes are used for searching users and for the uniqueness constraints on those columns. Values written by version 1.x show up as plain 40-character SHA-1 hashes until the row is rewritten.
3. Navigate to the table `USER_ENTITY_ENCRYPTED` to verify that those corresponding columns contain the encrypted values in the envelope format, e.g. `$$$v1:v1:<wrapped data key>:<ciphertext>` (the length varies). The first `v1` is the layout version, the second one (`v1`, `v2`, ...) is the version of the master key that wrapped the data key, and the rest is Base64.
4. Navigate to the table `USER_ATTRIBUTE`. Verify that the column `VALUE` for the rows corresponding to user attributes that have the encryption enabled contains a blind index value, similar to the columns in `USER_ENTITY` table.
5. Navigate to the table `USER_ATTRIBUTE_ENCRYPTED` to find the corresponding `VALUE` column contains the envelope-encrypted string, similar to the columns in `USER_ENTITY_ENCRYPTED` table.

Because every value is authenticated with AES-GCM and bound to its user and field
(AAD), a ciphertext copied to another row or another column will not decrypt and
will be reported in the log as a decryption failure instead of being shown.

## Known issues/limitations

1. Requires Keycloak version 24.x and above.
2. [Unmanaged attributes](https://www.keycloak.org/docs/latest/server_admin/#_understanding-managed-and-unmanaged-attributes) are not supported.
3. Encrypted user fields/attributes can only be searched using exact matches (the blind index is not reversible and does not support partial matches). Fuzzy-search is no longer possible for them.
4. If the encrypted values in the database cannot be decrypted for whatever reason, the hashed value of the fields/attributes will be displayed as-is to the users and clients. This may cause confusions.
5. If the `pii-data-encryption` validator is added to an existing attribute, the encryption is only applied to existing users' attribute data either when they are updated by the users, or if you switch the `Enable encryption` switch inside `User Entity Encryption` tab off and then on again.
6. Rotating a master key requires re-wrapping the data keys of existing rows (see *Key rotation*). Old keys must stay in the keyring until that backfill is done.

## Your contributions will be very much appreciated

### Issues

Please use the GitHub issues to report any issues you encounter when using this provider.

### Donation

Should you benefit from this Keycloak provider, I'd appreciate if you can buy me a coffee by clicking this button >>> [![Sponsor MLukman](https://img.shields.io/static/v1?label=Sponsor&message=%E2%9D%A4&logo=GitHub&color=%23fe8e86&logoSize=auto)](https://github.com/sponsors/MLukman)
