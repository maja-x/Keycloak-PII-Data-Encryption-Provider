/*
 * Copyright (C) 2025 Muhammad Lukman Nasaruddin <lukman.nasaruddin@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at 
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and 
 * limitations under the License.
 */
package my.unifi.eset.keycloak.piidataencryption.utils;

import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.persistence.NoResultException;
import jakarta.persistence.Query;
import java.util.Arrays;
import java.util.List;
import my.unifi.eset.keycloak.piidataencryption.admin.PiiDataEncryptionValidatorProvider;
import my.unifi.eset.keycloak.piidataencryption.crypto.BlindIndex;
import my.unifi.eset.keycloak.piidataencryption.crypto.PiiCipher;
import my.unifi.eset.keycloak.piidataencryption.crypto.PiiKind;
import my.unifi.eset.keycloak.piidataencryption.jpa.EncryptedUserAttributeEntity;
import my.unifi.eset.keycloak.piidataencryption.jpa.EncryptedUserEntity;
import my.unifi.eset.keycloak.piidataencryption.jpa.EncryptedUserProvider;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.jpa.entities.UserAttributeEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.userprofile.config.UPAttribute;
import org.keycloak.storage.jpa.JpaHashUtils;
import org.keycloak.userprofile.DeclarativeUserProfileProvider;
import org.keycloak.userprofile.UserProfileProvider;

/**
 * Provides core logics such as encryption/decryption of user entity & user
 * attribute entity, a few checks on whether or not the encryption feature is
 * enabled.
 *
 * @author MLukman (https://github.com/MLukman)
 */
public final class LogicUtils {

    static final Logger logger = Logger.getLogger(LogicUtils.class);

    /**
     * Enables/disables user encryption for a particular realm
     *
     * @param realm The RealmModel
     * @param enabled True to enable, false to disable
     */
    public static void setUserEncryptionEnabled(RealmModel realm, boolean enabled) {
        realm.setAttribute("users.encrypt", enabled);
        logger.debugf("Event: ENCRYPTION_%s, Realm: %s", enabled ? "ENABLED" : "DISABLED", realm.getId());
    }

    /**
     * Checks if the user encryption enabled or not
     *
     * @param ks KeycloakSession
     * @param realm RealmModel
     * @return true if enabled, false if disabled
     */
    public static boolean isUserEncryptionEnabled(KeycloakSession ks, RealmModel realm) {
        return ks.getProvider(UserProvider.class) instanceof EncryptedUserProvider
                && realm.getAttribute("users.encrypt", false);
    }

    /**
     * Checks if the user encryption enabled or not
     *
     * @param ks KeycloakSession
     * @param realmId Realm ID
     * @return true if enabled, false if disabled
     */
    public static boolean isUserEncryptionEnabled(KeycloakSession ks, String realmId) {
        return isUserEncryptionEnabled(ks, ks.realms().getRealm(realmId));
    }

    /**
     * Checks if a particular user attribute should be encrypted or not
     *
     * @param ks KeycloakSession
     * @param realmId The ID of the realm
     * @param attributeName The name of the user attribute
     * @return true if should encrypted, false if not
     */
    public static boolean shouldEncryptAttribute(KeycloakSession ks, String realmId, String attributeName) {
        return shouldEncryptAttribute(ks, realmId, attributeName, false);
    }

    /**
     * Checks if a particular user attribute should be encrypted or not
     *
     * @param ks KeycloakSession
     * @param realmId The ID of the realm
     * @param attributeName The name of the user attribute
     * @param force True to ignore whether the encryption is enabled for the
     * realm
     * @return true if should encrypted, false if not
     */
    public static boolean shouldEncryptAttribute(KeycloakSession ks, String realmId, String attributeName, boolean force) {
        if (attributeName == null || (!force && !isUserEncryptionEnabled(ks, realmId))) {
            return false;
        }
        if (attributeName.startsWith("pii-")) {
            return true;
        }
        try {
            UserProfileProvider upp = ks.getProvider(UserProfileProvider.class);
            if (upp instanceof DeclarativeUserProfileProvider dup) {
                UPAttribute upa = dup.getConfiguration().getAttribute(attributeName);
                if (upa != null && upa.getValidations().containsKey(PiiDataEncryptionValidatorProvider.ID)) {
                    return Boolean.parseBoolean(String.valueOf(upa.getValidations().get(PiiDataEncryptionValidatorProvider.ID).getOrDefault("enable", false)));
                }
            }
        } catch (Exception ex) {
            return false;
        }
        return false;
    }

    /**
     * Checks if a particular user attribute should be encrypted or not
     *
     * @param ks KeycloakSession
     * @param userAttributeEntity The UserAttributeEntity
     * @return true if should encrypted, false if not
     */
    public static boolean shouldEncryptAttribute(KeycloakSession ks, UserAttributeEntity userAttributeEntity) {
        return shouldEncryptAttribute(ks, userAttributeEntity, false);
    }

    /**
     * Checks if a particular user attribute should be encrypted or not
     *
     * @param ks KeycloakSession
     * @param userAttributeEntity The UserAttributeEntity
     * @param force True to ignore whether the encryption is enabled for the
     * realm
     * @return true if should encrypted, false if not
     */
    public static boolean shouldEncryptAttribute(KeycloakSession ks, UserAttributeEntity userAttributeEntity, boolean force) {
        return shouldEncryptAttribute(ks, userAttributeEntity.getUser().getRealmId(), userAttributeEntity.getName(), force);
    }

    /**
     * Gets the user entity with the specific ID
     *
     * @param em EntityManager
     * @param id User ID
     * @return
     */
    public static UserEntity getUserEntity(EntityManager em, String id) {
        return em.createQuery("SELECT u FROM UserEntity u WHERE u.id = :id", UserEntity.class)
                .setParameter("id", id)
                .getSingleResult();
    }

    /**
     * Gets existing encrypted user entity if exists, if not exists then either
     * create a new one or return null
     *
     * @param em EntityManager
     * @param ue The corresponding UserEntity
     * @param createIfMissing True if a new one should be created if missing,
     * false to simply return null
     * @return Either existing record, else if parameter createIfMissing is true
     * then a new record, else null
     */
    public static EncryptedUserEntity getEncryptedUserEntity(EntityManager em, UserEntity ue, boolean createIfMissing) {
        try {
            return em.createQuery("SELECT e FROM EncryptedUserEntity e WHERE e.user = :user", EncryptedUserEntity.class)
                    .setParameter("user", ue)
                    .getSingleResult();
        } catch (NoResultException ex) {
            if (createIfMissing) {
                return new EncryptedUserEntity(KeycloakModelUtils.generateId(), ue);
            }
            return null;
        }
    }

    /**
     * Gets existing encrypted user attribute entity if exists, if not exists
     * then either create a new one or return null
     *
     * @param em EntityManager
     * @param ue The corresponding UserEntity
     * @param name The attribute name
     * @param createIfMissing True if a new one should be created if missing,
     * false to simply return null
     * @return Either existing record, else if parameter createIfMissing is true
     * then a new record, else null
     */
    public static EncryptedUserAttributeEntity getEncryptedUserAttributeEntity(EntityManager em, UserEntity ue, String name, boolean createIfMissing) {
        try {
            return em.createQuery("SELECT e FROM EncryptedUserAttributeEntity e WHERE e.user = :user AND e.name = :name", EncryptedUserAttributeEntity.class)
                    .setParameter("user", ue)
                    .setParameter("name", name)
                    .getSingleResult();
        } catch (NoResultException ex) {
            if (createIfMissing) {
                return new EncryptedUserAttributeEntity(KeycloakModelUtils.generateId(), ue, name);
            }
            return null;
        }
    }

    /**
     * Number of processed users after which the progress of the migration is
     * logged, so a realm with thousands of users does not look stuck.
     */
    private static final int ENCRYPTION_PROGRESS_INTERVAL = 100;

    /**
     * Encrypts all existing user entities under a specific realm.
     *
     * <p>Each user is encrypted in its own transaction instead of all of them in
     * the transaction of the caller. A realm can have thousands of users, and
     * processing them in one transaction means keeping every user entity and its
     * row locks in the session until the request ends, and, because databases
     * such as PostgreSQL abort the whole transaction on the first failed
     * statement, a single user that cannot be encrypted makes every following
     * user fail with "current transaction is aborted" and leaves nothing behind.
     * With one transaction per user, the failure is reported against the user
     * that caused it while the users processed before it stay encrypted. Since an
     * already encrypted user is detected and skipped, the migration can simply be
     * run again to process the remaining users.</p>
     *
     * @param ks KeycloakSession
     * @param em EntityManager
     * @param realm The RealmModel to encrypt all of its users
     */
    public static void encryptExistingUserEntities(KeycloakSession ks, EntityManager em, RealmModel realm) {
        String realmId = realm.getId();
        List<String> userIds = em.createQuery("SELECT u.id FROM UserEntity u WHERE u.realmId = :realmId ORDER BY u.id", String.class)
                .setParameter("realmId", realmId)
                .getResultList();
        logger.infof("Event: REALM_USERS_ENCRYPTION_START, Realm: %s, Total Users: %d", realmId, userIds.size());

        KeycloakSessionFactory ksf = ks.getKeycloakSessionFactory();
        int encryptedCount = 0;
        int skippedCount = 0;
        int failureCount = 0;
        String firstFailedUser = null;

        for (String userId : userIds) {
            try {
                if (Boolean.TRUE.equals(KeycloakModelUtils.runJobInTransactionWithResult(ksf, session -> encryptUserInOwnTransaction(session, userId)))) {
                    encryptedCount++;
                } else {
                    skippedCount++;
                }
            } catch (RuntimeException ex) {
                failureCount++;
                if (firstFailedUser == null) {
                    firstFailedUser = userId;
                }
                logger.errorf(ex, "Failed to encrypt user %s in realm %s, its transaction has been rolled back", userId, realmId);
            }

            int processed = encryptedCount + skippedCount + failureCount;
            if (processed % ENCRYPTION_PROGRESS_INTERVAL == 0) {
                logger.infof("Event: REALM_USERS_ENCRYPTION_PROGRESS, Realm: %s, Processed: %d/%d, Encrypted: %d, Skipped: %d, Failed: %d",
                        realmId, processed, userIds.size(), encryptedCount, skippedCount, failureCount);
            }
        }

        logger.infof("Event: REALM_USERS_ENCRYPTION_COMPLETE, Realm: %s, Encrypted: %d, Skipped: %d, Failed: %d",
                realmId, encryptedCount, skippedCount, failureCount);

        if (failureCount > 0) {
            throw new IllegalStateException(String.format("Encrypted %d user(s) of realm %s, but %d user(s) failed, the first one being %s, "
                    + "so the realm configuration has not been saved. Fix the errors reported in the log for that user and save again: users that "
                    + "are already encrypted are skipped, so only the remaining users will be processed.",
                    encryptedCount, realmId, failureCount, firstFailedUser));
        }
    }

    /**
     * Encrypts a single user and its attributes in the transaction of the passed
     * session. The encryption is forced instead of being read from the realm
     * attribute, because that attribute is only saved by the caller after all
     * users have been processed.
     *
     * @param session The KeycloakSession of the transaction to use
     * @param userId The ID of the user to encrypt
     * @return true if the user was encrypted, false if it was skipped
     */
    private static boolean encryptUserInOwnTransaction(KeycloakSession session, String userId) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        UserEntity user = em.find(UserEntity.class, userId);
        if (user == null) {
            logger.warnf("Event: USER_ENCRYPTION_SKIPPED_NOT_FOUND, User: %s", userId);
            return false;
        }
        if (user.getServiceAccountClientLink() != null) {
            logger.debugf("Event: USER_ENCRYPTION_SKIPPED_SERVICE_ACCOUNT, User: %s", userId);
            return false; // service accounts do not have PII to encrypt
        }
        encryptUserEntity(session, em, user, true);
        for (UserAttributeEntity uae : user.getAttributes()) {
            encryptUserAttributeEntity(session, em, uae, true);
        }
        em.flush();
        logger.debugf("Event: USER_ENCRYPTION, Realm: %s, User: %s", user.getRealmId(), userId);
        return true;
    }

    /**
     * Encrypts an existing user entity
     *
     * @param ks KeycloakSession
     * @param em EntityManager
     * @param ue The UserEntity to encrypt
     */
    public static void encryptUserEntity(KeycloakSession ks, EntityManager em, UserEntity ue) {
        encryptUserEntity(ks, em, ue, false);
    }

    /**
     * Encrypts an existing user entity
     *
     * @param ks KeycloakSession
     * @param em EntityManager
     * @param ue The UserEntity to encrypt
     * @param force True to encrypt even when the encryption is not enabled for
     * the realm yet, e.g. while the configuration is still being saved
     */
    public static void encryptUserEntity(KeycloakSession ks, EntityManager em, UserEntity ue, boolean force) {
        if (ue == null) {
            return;
        }
        if (!force && !LogicUtils.isUserEncryptionEnabled(ks, ue.getRealmId())) {
            return;
        }

        // Re-fetch and lock the user entity to prevent concurrent modifications
        ue = em.find(UserEntity.class, ue.getId(), LockModeType.PESSIMISTIC_WRITE);
        if (ue == null) {
            return;
        }

        EncryptedUserEntity eue = LogicUtils.getEncryptedUserEntity(em, ue, true);
        if (isHash(ue.getUsername())) {
            // somehow the value is already hashed so we skip it to avoid double hash/encrypt
            return;
        }
        PiiCipher cipher = PiiCipher.getInstance();
        eue.setUsername(cipher.encryptString(ue.getUsername(), aad(ue.getId(), "username")));

        // Handle null email safely
        String emailNormalized = ue.getEmail() != null ? ue.getEmail().trim() : "";
        if (emailNormalized.isBlank()) {
            emailNormalized = "";
        }
        eue.setEmail(cipher.encryptString(emailNormalized, aad(ue.getId(), "email")));

        String firstName = ue.getFirstName() != null ? ue.getFirstName().trim() : "";
        String lastName = ue.getLastName() != null ? ue.getLastName().trim() : "";
        if (firstName.isBlank()) {
            firstName = "";
        }
        if (lastName.isBlank()) {
            lastName = "";
        }

        eue.setFirstName(cipher.encryptString(firstName, aad(ue.getId(), "firstName")));
        eue.setLastName(cipher.encryptString(lastName, aad(ue.getId(), "lastName")));
        em.persist(eue);
        em.flush(); // Ensure the encrypted entity is persisted before updating the original user entity

        Query update = em.createQuery("UPDATE UserEntity u SET u.username = :username, u.email = :email, u.emailConstraint = :emailConstraint, u.firstName = :firstName, u.lastName = :lastName WHERE u.id = :id");
        update.setParameter("id", ue.getId());
        update.setParameter("username", hash(ue.getUsername()));
        
        // Handle email hash safely
        String emailHash = emailNormalized.isEmpty() ? null : hash(emailNormalized);
        update.setParameter("email", emailHash);

        // Handle emailConstraint with unique constraint consideration
        if (!ks.realms().getRealm(ue.getRealmId()).isDuplicateEmailsAllowed()) {
            if (emailHash != null) {
                update.setParameter("emailConstraint", emailHash);
            } else {
                // Preserve the original UUID emailConstraint for users without email
                update.setParameter("emailConstraint", ue.getEmailConstraint());
            }
        } else {
            update.setParameter("emailConstraint", ue.getEmailConstraint());
        }
        
        update.setParameter("firstName", hash(firstName));
        update.setParameter("lastName", hash(lastName));
        update.executeUpdate();
    }

    /**
     * Encrypts an existing user attribute entity
     *
     * @param ks KeycloakSession
     * @param em EntityManager
     * @param uae The UserAttributeEntity to encrypt
     */
    public static void encryptUserAttributeEntity(KeycloakSession ks, EntityManager em, UserAttributeEntity uae) {
        encryptUserAttributeEntity(ks, em, uae, false);
    }

    /**
     * Encrypts an existing user attribute entity
     *
     * @param ks KeycloakSession
     * @param em EntityManager
     * @param uae The UserAttributeEntity to encrypt
     * @param force True to encrypt even when the encryption is not enabled for
     * the realm yet, e.g. while the configuration is still being saved
     */
    public static void encryptUserAttributeEntity(KeycloakSession ks, EntityManager em, UserAttributeEntity uae, boolean force) {
      if (shouldEncryptAttribute(ks, uae, force)) {
          String value = uae.getValue();
          
          // Null/empty safety check
          if (value == null || value.isEmpty()) {
              return;
          }
          
          if (isHash(value)) {
              // somehow the value is already hashed so we skip it to avoid double hash/encrypt
              return;
          }
          
          // Re-fetch and lock the attribute entity to prevent concurrent modifications
          UserAttributeEntity lockedUae = em.find(UserAttributeEntity.class, uae.getId(), LockModeType.PESSIMISTIC_WRITE);
          if (lockedUae == null || lockedUae.getValue() == null) {
              logger.debugf("Event: ATTRIBUTE_ENCRYPTION_SKIPPED_NOT_FOUND, User: %s, Attribute: %s", uae.getUser().getId(), uae.getName());
              return;
          }
          
          // Use the locked entity's value
          value = lockedUae.getValue();
          
          EncryptedUserAttributeEntity euae = getEncryptedUserAttributeEntity(em, lockedUae.getUser(), lockedUae.getName(), true);
          String encryptedValue = PiiCipher.getInstance().encryptString(value, attributeAad(lockedUae.getUser().getId(), lockedUae.getName()));
          euae.setValue(encryptedValue);
          euae.setAttribute(lockedUae);
          em.persist(euae);
          em.flush(); // Ensure encrypted entity is persisted before updating original
          
          // Generate consistent hashes
          String valueHash = hash(value);
          byte[] jpHash = JpaHashUtils.hashForAttributeValue(value);
          byte[] jpHashLower = JpaHashUtils.hashForAttributeValueLowerCase(value);
          
          if (value.length() > 255) {
              Query update = em.createQuery("UPDATE UserAttributeEntity u SET u.value = null, u.longValue = :longValue, u.longValueHash = :longValueHash, u.longValueHashLowerCase = :longValueHashLowerCase WHERE u.id = :id");
              update.setParameter("id", lockedUae.getId());
              update.setParameter("longValue", valueHash);
              update.setParameter("longValueHash", jpHash);
              update.setParameter("longValueHashLowerCase", jpHashLower);
              update.executeUpdate();
          } else {
              Query update = em.createQuery("UPDATE UserAttributeEntity u SET u.value = :value, u.longValue = null, u.longValueHash = null, u.longValueHashLowerCase = null WHERE u.id = :id");
              update.setParameter("id", lockedUae.getId());
              update.setParameter("value", valueHash);
              update.executeUpdate();
          }
      }
    }

    /**
     * Decrypts all existing user entities under a specific realm
     *
     * @param ksf KeycloakSessionFactory
     * @param realm RealmModel
     */
    public static void decryptExistingUserEntities(KeycloakSessionFactory ksf, RealmModel realm) {
        String realmId = realm.getId();
        
        // Get all user IDs in a single query
        KeycloakSession ks = ksf.create();
        List<String> userIds;
        try {
            EntityManager em = ks.getProvider(JpaConnectionProvider.class).getEntityManager();
            userIds = em.createQuery("SELECT u.id FROM UserEntity u WHERE u.realmId = :realmId ORDER BY u.id", String.class)
                    .setParameter("realmId", realmId)
                    .getResultList();
        } finally {
            ks.close();
        }
        
        logger.infof("Event: REALM_USERS_DECRYPTION_START, Realm: %s, Total Users: %d", realmId, userIds.size());

        int decryptedCount = 0;
        int failureCount = 0;

        for (String userId : userIds) {
            try {
                KeycloakModelUtils.runJobInTransaction(ksf, session -> {
                    EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
                    UserEntity user = em.find(UserEntity.class, userId);
                    if (user != null) {
                        EncryptedUserEntity eue = getEncryptedUserEntity(em, user, false);
                        if (eue != null) {
                            decryptUserEntity(em, realm, eue);
                            logger.debugf("Event: USER_DECRYPTION, Realm: %s, User: %s", realmId, userId);
                        }
                        List<EncryptedUserAttributeEntity> encryptedAttributes = em.createQuery("SELECT a FROM EncryptedUserAttributeEntity a WHERE a.user = :user", EncryptedUserAttributeEntity.class)
                                .setParameter("user", user)
                                .getResultList();
                        for (EncryptedUserAttributeEntity euae : encryptedAttributes) {
                            decryptUserAttributeEntity(em, realm, euae);
                        }
                    }
                });
                decryptedCount++;
            } catch (DecryptionFailureException ex) {
                failureCount++;
                ex.outputToLog(logger);
            } catch (RuntimeException ex) {
                failureCount++;
                logger.errorf(ex, "Event: USER_DECRYPTION_FAILED, Realm: %s, User: %s, Error: %s", realmId, userId, ex.getMessage());
            }

            int processed = decryptedCount + failureCount;
            if (processed % ENCRYPTION_PROGRESS_INTERVAL == 0) {
                logger.infof("Event: REALM_USERS_DECRYPTION_PROGRESS, Realm: %s, Processed: %d/%d, Decrypted: %d, Failed: %d",
                        realmId, processed, userIds.size(), decryptedCount, failureCount);
            }
        }

        logger.infof("Event: REALM_USERS_DECRYPTION_COMPLETE, Realm: %s, Decrypted: %d, Failed: %d",
                realmId, decryptedCount, failureCount);
    }

    /**
     * Decrypts an encrypted user entity
     *
     * @param em EntityManager
     * @param realm RealmModel
     * @param eue EncryptedUserEntity
     */
    public static void decryptUserEntity(EntityManager em, RealmModel realm, EncryptedUserEntity eue) {
    //     UserEntity user = eue.getUser();
    //     PiiCipher cipher = PiiCipher.getInstance();
    //     String username = cipher.decryptString(eue.getUsername(), aad(user.getId(), "username"));
    //     if (!user.getUsername().equalsIgnoreCase(username)) {
    //         throw new DecryptionFailureException(realm.getId(), user.getId());
    //     }
    //     Query update = em.createQuery("UPDATE UserEntity u SET u.username = :username, u.email = :email, u.emailConstraint = :emailConstraint, u.firstName = :firstName, u.lastName = :lastName WHERE u.id = :id");
    //     update.setParameter("id", user.getId());
    //     update.setParameter("username", username);
    //     String decryptedEmail = cipher.decryptString(eue.getEmail(), aad(user.getId(), "email"));
    //     update.setParameter("email", decryptedEmail);
    //     if (!realm.isDuplicateEmailsAllowed()) {
    //         update.setParameter("emailConstraint", decryptedEmail);
    //     } else {
    //         update.setParameter("emailConstraint", user.getEmailConstraint()); // basically no change
    //     }
    //     update.setParameter("firstName", cipher.decryptString(eue.getFirstName(), aad(user.getId(), "firstName")));
    //     update.setParameter("lastName", cipher.decryptString(eue.getLastName(), aad(user.getId(), "lastName")));
    //     update.executeUpdate();
    //     em.remove(eue);
        
        // Re-fetch and lock to prevent concurrent modifications
        UserEntity user = em.find(UserEntity.class, eue.getUser().getId(), LockModeType.PESSIMISTIC_WRITE);
        if (user == null) {
            return;
        }
        
        PiiCipher cipher = PiiCipher.getInstance();
        
        // Decrypt all fields
        String decryptedUsername = cipher.decryptString(eue.getUsername(), aad(user.getId(), "username"));
        String decryptedEmail = cipher.decryptString(eue.getEmail(), aad(user.getId(), "email"));
        String decryptedFirstName = cipher.decryptString(eue.getFirstName(), aad(user.getId(), "firstName"));
        String decryptedLastName = cipher.decryptString(eue.getLastName(), aad(user.getId(), "lastName"));
        
        // Validate username hash matches
        if (!matchesHash(user.getUsername(), decryptedUsername)) {
            throw new DecryptionFailureException(realm.getId(), user.getId());
        }
        
        // Validate email hash matches (handle empty string case)
        String emailNormalized = decryptedEmail != null && !decryptedEmail.isBlank() ? decryptedEmail : "";
        // Always validate email hash, even if empty
        if (!matchesHash(user.getEmail(), emailNormalized)) {
            throw new DecryptionFailureException(realm.getId(), user.getId());
        }
        
        // Validate firstName and lastName hashes
        if (!matchesHash(user.getFirstName(), decryptedFirstName)) {
            throw new DecryptionFailureException(realm.getId(), user.getId());
        }
        if (!matchesHash(user.getLastName(), decryptedLastName)) {
            throw new DecryptionFailureException(realm.getId(), user.getId());
        }
        
        // All validations passed, update with decrypted values
        Query update = em.createQuery("UPDATE UserEntity u SET u.username = :username, u.email = :email, u.emailConstraint = :emailConstraint, u.firstName = :firstName, u.lastName = :lastName WHERE u.id = :id");
        update.setParameter("id", user.getId());
        update.setParameter("username", decryptedUsername);
        
        // Restore email with proper null handling
        update.setParameter("email", emailNormalized.isEmpty() ? null : emailNormalized);
        
        // Restore emailConstraint based on realm config
        if (!realm.isDuplicateEmailsAllowed()) {
            update.setParameter("emailConstraint", emailNormalized.isEmpty() ? user.getId() : emailNormalized);
        } else {
            update.setParameter("emailConstraint", user.getId()); // Use user ID for non-duplicate realms
        }
        
        update.setParameter("firstName", decryptedFirstName);
        update.setParameter("lastName", decryptedLastName);
        update.executeUpdate();
        
        em.remove(eue);
    }

    /**
     * Decrypts an encrypted user attribute entity
     *
     * @param em EntityManager
     * @param realm RealmModel
     * @param euae EncryptedUserAttributeEntity
     */
    public static void decryptUserAttributeEntity(EntityManager em, RealmModel realm, EncryptedUserAttributeEntity euae) {
        // UserAttributeEntity uae = euae.getAttribute();
        // String value = PiiCipher.getInstance().decryptString(euae.getValue(), attributeAad(euae.getUser().getId(), euae.getName()));
        //
        // String storedValue = uae.getValue();
        // if (storedValue == null || !value.equalsIgnoreCase(storedValue)) {
        //     throw new DecryptionFailureException(realm.getId(), euae.getUser().getId(), euae.getName());
        // }
        //
        // if (value.length() > 255) {
        //     Query update = em.createQuery("UPDATE UserAttributeEntity u SET u.value = null, u.longValue = :longValue, u.longValueHash = :longValueHash, u.longValueHashLowerCase = :longValueHashLowerCase WHERE u.id = :id");
        //     update.setParameter("id", uae.getId());
        //     update.setParameter("longValue", value);
        //     update.setParameter("longValueHash", JpaHashUtils.hashForAttributeValue(value));
        //     update.setParameter("longValueHashLowerCase", JpaHashUtils.hashForAttributeValueLowerCase(value));
        //     update.executeUpdate();
        // } else {
        //     Query update = em.createQuery("UPDATE UserAttributeEntity u SET u.value = :value, u.longValue = null, u.longValueHash = null, u.longValueHashLowerCase = null WHERE u.id = :id");
        //     update.setParameter("id", uae.getId());
        //     update.setParameter("value", value);
        //     update.executeUpdate();
        // }
        // em.remove(euae);

        UserAttributeEntity uae = euae.getAttribute();
        
        // Re-fetch and lock to prevent concurrent modifications
        UserAttributeEntity lockedUae = em.find(UserAttributeEntity.class, uae.getId(), LockModeType.PESSIMISTIC_WRITE);
        if (lockedUae == null) {
            return;
        }
        
        String decryptedValue = PiiCipher.getInstance().decryptString(euae.getValue(), attributeAad(euae.getUser().getId(), euae.getName()));
        
        // Determine which stored value to validate against. Values longer than
        // 255 characters are stored in LONG_VALUE instead of VALUE, and Keycloak
        // keeps LONG_VALUE and its hashes private on UserAttributeEntity with no
        // getters, so they are read with a native query.
        String storedValue;
        boolean isLongValue;
        List<?> longValueRows = em.createNativeQuery("SELECT LONG_VALUE, LONG_VALUE_HASH FROM USER_ATTRIBUTE WHERE ID = :id")
                .setParameter("id", lockedUae.getId())
                .getResultList();
        Object[] longValueRow = longValueRows.isEmpty() ? null : (Object[]) longValueRows.get(0);
        if (longValueRow != null && longValueRow[0] != null) {
            isLongValue = true;
            storedValue = (String) longValueRow[0];

            // Verify the JPA attribute lookup hash if it was stored
            if (longValueRow[1] instanceof byte[] storedJpaHash
                    && !Arrays.equals(storedJpaHash, JpaHashUtils.hashForAttributeValue(decryptedValue))) {
                throw new DecryptionFailureException(realm.getId(), euae.getUser().getId(), euae.getName());
            }
        } else {
            isLongValue = false;
            storedValue = lockedUae.getValue();
        }

        // Validate decrypted value matches the stored blind index hash
        if (storedValue == null
                || (isLongValue ? !storedValue.equalsIgnoreCase(hash(decryptedValue)) : !matchesHash(storedValue, decryptedValue))) {
            throw new DecryptionFailureException(realm.getId(), euae.getUser().getId(), euae.getName());
        }
        
        // Update with original decrypted value
        if (decryptedValue.length() > 255) {
            Query update = em.createQuery("UPDATE UserAttributeEntity u SET u.value = null, u.longValue = :longValue, u.longValueHash = :longValueHash, u.longValueHashLowerCase = :longValueHashLowerCase WHERE u.id = :id");
            update.setParameter("id", lockedUae.getId());
            update.setParameter("longValue", decryptedValue);
            update.setParameter("longValueHash", JpaHashUtils.hashForAttributeValue(decryptedValue));
            update.setParameter("longValueHashLowerCase", JpaHashUtils.hashForAttributeValueLowerCase(decryptedValue));
            update.executeUpdate();
        } else {
            Query update = em.createQuery("UPDATE UserAttributeEntity u SET u.value = :value, u.longValue = null, u.longValueHash = null, u.longValueHashLowerCase = null WHERE u.id = :id");
            update.setParameter("id", lockedUae.getId());
            update.setParameter("value", decryptedValue);
            update.executeUpdate();
        }
        em.remove(euae);
    }

    /**
     * Builds the AAD that binds an encrypted user field to its user and field
     * name.
     *
     * @param userId The user ID
     * @param field The field name
     * @return The AAD
     */
    public static String aad(String userId, String field) {
        return PiiCipher.fieldContext("user", userId, field);
    }

    /**
     * Builds the AAD that binds an encrypted user attribute to its user and
     * attribute name.
     *
     * @param userId The user ID
     * @param attributeName The attribute name
     * @return The AAD
     */
    public static String attributeAad(String userId, String attributeName) {
        return PiiCipher.fieldContext("user", userId, "attribute:" + attributeName);
    }

    /**
     * Generates the blind index to be stored in place of the plain text value.
     * The hash is an HMAC-SHA256 keyed with the configured pepper, so matching
     * can only be done by Keycloak and not by whoever gets hold of the database.
     *
     * @param raw The plain text value
     * @return The blind index of the input raw
     */
    public static String hash(String raw) {
        return PiiCipher.getInstance().search(raw, PiiKind.GENERIC);
    }

    /**
     * Checks whether a stored value is a blind index, either the HMAC-SHA256
     * format of this version or the SHA-1 format of version 1.x.
     *
     * @param value The value to check
     * @return true if the value is a blind index
     */
    public static boolean isHash(String value) {
        return BlindIndex.isHash(value);
    }

    /**
     * Checks whether a stored blind index matches a plain text value.
     *
     * @param storedHash The hash stored in the database
     * @param raw The plain text value
     * @return true if the hash matches the value
     */
    public static boolean matchesHash(String storedHash, String raw) {
        return raw != null && PiiCipher.getInstance().matchesHash(storedHash, raw, PiiKind.GENERIC);
    }

    // Makes this class un-instantiatable
    private LogicUtils() {
    }

}
