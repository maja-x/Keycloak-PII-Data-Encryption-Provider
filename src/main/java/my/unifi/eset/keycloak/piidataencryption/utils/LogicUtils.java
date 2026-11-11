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
import java.util.List;
import my.unifi.eset.keycloak.piidataencryption.admin.PiiDataEncryptionValidatorProvider;
import my.unifi.eset.keycloak.piidataencryption.crypto.BlindIndex;
import my.unifi.eset.keycloak.piidataencryption.crypto.PiiCipher;
import my.unifi.eset.keycloak.piidataencryption.crypto.PiiKind;
import my.unifi.eset.keycloak.piidataencryption.jpa.EncryptedUserAttributeEntity;
import my.unifi.eset.keycloak.piidataencryption.jpa.EncryptedUserEntity;
import my.unifi.eset.keycloak.piidataencryption.jpa.EncryptedUserProvider;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
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
        if (attributeName == null || !isUserEncryptionEnabled(ks, realmId)) {
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
        return shouldEncryptAttribute(ks, userAttributeEntity.getUser().getRealmId(), userAttributeEntity.getName());
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
     * Encrypts all existing user entities under a specific realm
     *
     * @param ks KeycloakSession
     * @param em EntityManager
     * @param realm The RealmModel to encrypt all of its users
     */
    public static void encryptExistingUserEntities(KeycloakSession ks, EntityManager em, RealmModel realm) {
        List<UserEntity> realmUsers = em.createQuery("SELECT u FROM UserEntity u WHERE u.realmId = :realmId", UserEntity.class)
                .setParameter("realmId", realm.getId())
                .getResultList();
        logger.debugf("Event: REALM_USERS_ENCRYPTION, Realm: %s, Total Users: %s", realm.getId(), realmUsers.size());

        int successCount = 0;
        int failureCount = 0;

        for (int i = 0; i < realmUsers.size(); i++) {
            UserEntity user = realmUsers.get(i);

            try {
                if (user.getServiceAccountClientLink() != null) {
                    continue; // skip service accounts
                }

                encryptUserEntity(ks, em, user);
                logger.debugf("Event: USER_ENCRYPTION, Realm: %s, User: %s", realm.getId(), user.getId());

                for (UserAttributeEntity uae : user.getAttributes()) {
                    encryptUserAttributeEntity(ks, em, uae);
                }

                successCount++;

            } catch (Exception ex) {
                failureCount++;
                logger.errorf("Failed to encrypt user %s in realm %s: %s", user.getId(), realm.getId(), ex.getMessage());
            }
        }

        logger.infof("Event: REALM_USERS_ENCRYPTION_COMPLETE, Realm: %s, Success: %d, Failure: %d",
                realm.getId(), successCount, failureCount);
    }

    /**
     * Encrypts an existing user entity
     *
     * @param ks KeycloakSession
     * @param em EntityManager
     * @param ue The UserEntity to encrypt
     */
    public static void encryptUserEntity(KeycloakSession ks, EntityManager em, UserEntity ue) {
        if (ue == null) {
            return;
        }
        if (!LogicUtils.isUserEncryptionEnabled(ks, ue.getRealmId())) {
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
        String emailToEncrypt = ue.getEmail() != null ? ue.getEmail() : "";
        eue.setEmail(cipher.encryptString(emailToEncrypt, aad(ue.getId(), "email")));

        String firstName = ue.getFirstName() != null ? ue.getFirstName() : "";
        String lastName = ue.getLastName() != null ? ue.getLastName() : "";

        eue.setFirstName(cipher.encryptString(firstName, aad(ue.getId(), "firstName")));
        eue.setLastName(cipher.encryptString(lastName, aad(ue.getId(), "lastName")));
        em.persist(eue);

        Query update = em.createQuery("UPDATE UserEntity u SET u.username = :username, u.email = :email, u.emailConstraint = :emailConstraint, u.firstName = :firstName, u.lastName = :lastName WHERE u.id = :id");
        update.setParameter("id", ue.getId());
        update.setParameter("username", hash(ue.getUsername()));
        
        // Handle email hash safely
        String emailHash = null;
        if (ue.getEmail() != null && !ue.getEmail().isBlank()) {
            emailHash = hash(ue.getEmail());
        }
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
        if (shouldEncryptAttribute(ks, uae)) {
            String value = uae.getValue();
            if (isHash(value)) {
                // somehow the value is already hashed so we skip it to avoid double hash/encrypt
                return;
            }
            EncryptedUserAttributeEntity euae = getEncryptedUserAttributeEntity(em, uae.getUser(), uae.getName(), true);
            euae.setValue(PiiCipher.getInstance().encryptString(value, attributeAad(uae.getUser().getId(), uae.getName())));
            euae.setAttribute(uae);
            em.persist(euae);
            if (value.length() > 255) {
                Query update = em.createQuery("UPDATE UserAttributeEntity u SET u.value = null, u.longValue = :longValue, u.longValueHash = :longValueHash, u.longValueHashLowerCase = :longValueHashLowerCase WHERE u.id = :id");
                update.setParameter("id", uae.getId());
                update.setParameter("longValue", hash(value));
                update.setParameter("longValueHash", JpaHashUtils.hashForAttributeValue(value));
                update.setParameter("longValueHashLowerCase", JpaHashUtils.hashForAttributeValueLowerCase(value));
                update.executeUpdate();
            } else {
                Query update = em.createQuery("UPDATE UserAttributeEntity u SET u.value = :value, u.longValue = null, u.longValueHash = null, u.longValueHashLowerCase = null WHERE u.id = :id");
                update.setParameter("id", uae.getId());
                update.setParameter("value", hash(value));
                update.executeUpdate();
            }
        }
    }

    /**
     * Decrypts all existing user entities under a specific realm
     *
     * @param em EntityManager
     * @param realm RealmModel
     */
    public static void decryptExistingUserEntities(EntityManager em, RealmModel realm) {
        List<UserEntity> realmUsers = em.createQuery("SELECT u FROM UserEntity u WHERE u.realmId = :realmId", UserEntity.class).setParameter("realmId", realm.getId()).getResultList();
        for (UserEntity user : realmUsers) {
            try {
                EncryptedUserEntity eue = getEncryptedUserEntity(em, user, false);
                if (eue != null) {
                    decryptUserEntity(em, realm, eue);
                    logger.debugf("Event: USER_DECRYPTION, Realm: %s, User: %s", realm.getId(), user.getId());
                }
                List<EncryptedUserAttributeEntity> encryptedAttributes = em.createQuery("SELECT a FROM EncryptedUserAttributeEntity a WHERE a.user = :user", EncryptedUserAttributeEntity.class).setParameter("user", user).getResultList();
                for (EncryptedUserAttributeEntity euae : encryptedAttributes) {
                    decryptUserAttributeEntity(em, realm, euae);
                }
            } catch (DecryptionFailureException ex) {
                ex.outputToLog(logger);
            }
        }
    }

    /**
     * Decrypts an encrypted user entity
     *
     * @param em EntityManager
     * @param realm RealmModel
     * @param eue EncryptedUserEntity
     */
    public static void decryptUserEntity(EntityManager em, RealmModel realm, EncryptedUserEntity eue) {
        UserEntity user = eue.getUser();
        PiiCipher cipher = PiiCipher.getInstance();
        String username = cipher.decryptString(eue.getUsername(), aad(user.getId(), "username"));
        if (!user.getUsername().equalsIgnoreCase(username)) {
            throw new DecryptionFailureException(realm.getId(), user.getId());
        }
        Query update = em.createQuery("UPDATE UserEntity u SET u.username = :username, u.email = :email, u.emailConstraint = :emailConstraint, u.firstName = :firstName, u.lastName = :lastName WHERE u.id = :id");
        update.setParameter("id", user.getId());
        update.setParameter("username", username);
        String decryptedEmail = cipher.decryptString(eue.getEmail(), aad(user.getId(), "email"));
        update.setParameter("email", decryptedEmail);
        if (!realm.isDuplicateEmailsAllowed()) {
            update.setParameter("emailConstraint", decryptedEmail);
        } else {
            update.setParameter("emailConstraint", user.getEmailConstraint()); // basically no change
        }
        update.setParameter("firstName", cipher.decryptString(eue.getFirstName(), aad(user.getId(), "firstName")));
        update.setParameter("lastName", cipher.decryptString(eue.getLastName(), aad(user.getId(), "lastName")));
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
        UserAttributeEntity uae = euae.getAttribute();
        String value = PiiCipher.getInstance().decryptString(euae.getValue(), attributeAad(euae.getUser().getId(), euae.getName()));
        if (!value.equalsIgnoreCase(uae.getValue())) {
            throw new DecryptionFailureException(realm.getId(), euae.getUser().getId(), euae.getName());
        }
        if (value.length() > 255) {
            Query update = em.createQuery("UPDATE UserAttributeEntity u SET u.value = null, u.longValue = :longValue, u.longValueHash = :longValueHash, u.longValueHashLowerCase = :longValueHashLowerCase WHERE u.id = :id");
            update.setParameter("id", uae.getId());
            update.setParameter("longValue", value);
            update.setParameter("longValueHash", JpaHashUtils.hashForAttributeValue(value));
            update.setParameter("longValueHashLowerCase", JpaHashUtils.hashForAttributeValueLowerCase(value));
            update.executeUpdate();
        } else {
            Query update = em.createQuery("UPDATE UserAttributeEntity u SET u.value = :value, u.longValue = null, u.longValueHash = null, u.longValueHashLowerCase = null WHERE u.id = :id");
            update.setParameter("id", uae.getId());
            update.setParameter("value", value);
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
