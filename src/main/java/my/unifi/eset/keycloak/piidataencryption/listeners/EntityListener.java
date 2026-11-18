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
package my.unifi.eset.keycloak.piidataencryption.listeners;

import my.unifi.eset.keycloak.piidataencryption.crypto.PiiCipher;
import my.unifi.eset.keycloak.piidataencryption.utils.LogicUtils;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import java.util.HashMap;
import java.util.Map;
import my.unifi.eset.keycloak.piidataencryption.jpa.EncryptedRealmSmtpConfigEntity;
import my.unifi.eset.keycloak.piidataencryption.jpa.EncryptedUserAttributeEntity;
import my.unifi.eset.keycloak.piidataencryption.jpa.EncryptedUserEntity;
import my.unifi.eset.keycloak.piidataencryption.utils.DecryptionFailureException;
import org.hibernate.boot.Metadata;
import org.hibernate.boot.spi.BootstrapContext;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.event.service.spi.EventListenerRegistry;
import org.hibernate.event.spi.EventType;
import org.hibernate.event.spi.PreInsertEvent;
import org.hibernate.event.spi.PreInsertEventListener;
import org.hibernate.event.spi.PreLoadEvent;
import org.hibernate.event.spi.PreLoadEventListener;
import org.hibernate.event.spi.PreUpdateEvent;
import org.hibernate.event.spi.PreUpdateEventListener;
import org.hibernate.integrator.spi.Integrator;
import org.hibernate.service.spi.SessionFactoryServiceRegistry;
import org.jboss.logging.Logger;
import org.keycloak.models.jpa.entities.RealmEntity;
import org.keycloak.models.jpa.entities.UserAttributeEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.storage.jpa.JpaHashUtils;
import java.util.Map;

/**
 * Listens to PreLoad, PreInsert, and PreUpdate entity events to perform
 * decryption/encryption of UserEntity & UserAttributeEntity
 *
 * @author MLukman (https://github.com/MLukman)
 */
public class EntityListener implements Integrator, PreLoadEventListener, PreInsertEventListener, PreUpdateEventListener {

    static final Logger logger = Logger.getLogger(EntityListener.class);

    @Override
    public void integrate(Metadata metadata, BootstrapContext bootstrapContext, SessionFactoryImplementor sessionFactory) {
        EventListenerRegistry eventListenerRegistry = sessionFactory.getServiceRegistry().getService(EventListenerRegistry.class);
        eventListenerRegistry.appendListeners(EventType.PRE_LOAD, this);
        eventListenerRegistry.appendListeners(EventType.PRE_INSERT, this);
        eventListenerRegistry.appendListeners(EventType.PRE_UPDATE, this);
    }

    @Override
    public void disintegrate(SessionFactoryImplementor sfi, SessionFactoryServiceRegistry sfsr) {
    }

    @Override
    public void onPreLoad(PreLoadEvent ple) {
        try {
            if (ple.getEntity() instanceof UserEntity ue) {
                handlePreLoadEventUserEntity(ple, ue);
            }
            if (ple.getEntity() instanceof UserAttributeEntity uae) {
                handlePreLoadEventUserAttributeEntity(ple, uae);
            }
        } catch (DecryptionFailureException ex) {
            ex.outputToLog(logger);
        }
    }

    @Override
    public boolean onPreInsert(PreInsertEvent ple) {
        try {
            if (ple.getEntity() instanceof UserEntity ue) {
                handlePreInsertUserEntity(ple, ue);
            }
            if (ple.getEntity() instanceof UserAttributeEntity uae) {
                handlePreInsertUserAttributeEntity(ple, uae);
            }
            if (ple.getEntity() instanceof RealmEntity re) {
                handlePreInsertRealmEntity(ple, re);
            }
        } catch (DecryptionFailureException ex) {
            ex.outputToLog(logger);
        }
        return false;
    }

    @Override
    public boolean onPreUpdate(PreUpdateEvent ple) {
        try {
            if (ple.getEntity() instanceof UserEntity ue) {
                handlePreUpdateUserEntity(ple, ue);
            }
            if (ple.getEntity() instanceof UserAttributeEntity uae) {
                handlePreUpdateUserAttributeEntity(ple, uae);
            }
            if (ple.getEntity() instanceof RealmEntity re) {
                handlePreUpdateRealmEntity(ple, re);
            }
        } catch (DecryptionFailureException ex) {
            ex.outputToLog(logger);
        }
        return false;
    }

    protected void handlePreLoadEventUserEntity(PreLoadEvent ple, UserEntity ue) {
        EntityManager em = (EntityManager) ple.getSession();
        EncryptedUserEntity eue = LogicUtils.getEncryptedUserEntity(em, ue, false);
        if (eue != null) {
            Map<String, Integer> cols = collectColumnIndices(ple.getPersister().getEntityMetamodel().getPropertyNames());
            Object[] states = ple.getState();
            if (!LogicUtils.isHash((String) states[cols.get("username")])) {
                // skip because the entity is already decrypted
                logger.debugf("Event: USER_ALREADY_DECRYPTED, Realm: %s, User: %s", states[cols.get("realmId")], ue.getId());
            } else if (validateHashValueVsEncryptedValue((String) states[cols.get("username")], eue.getUsername(), LogicUtils.aad(ue.getId(), "username"))) {
                logger.debugf("Event: USER_DECRYPTION, Realm: %s, User: %s", states[cols.get("realmId")], ue.getId());
                PiiCipher cipher = PiiCipher.getInstance();
                states[cols.get("username")] = cipher.decryptString(eue.getUsername(), LogicUtils.aad(ue.getId(), "username"));
                states[cols.get("email")] = cipher.decryptString(eue.getEmail(), LogicUtils.aad(ue.getId(), "email"));
                states[cols.get("firstName")] = cipher.decryptString(eue.getFirstName(), LogicUtils.aad(ue.getId(), "firstName"));
                states[cols.get("lastName")] = cipher.decryptString(eue.getLastName(), LogicUtils.aad(ue.getId(), "lastName"));
            } else {
                throw new DecryptionFailureException((String) states[cols.get("realmId")], ue.getId());
            }
        }
    }

    protected void handlePreLoadEventUserAttributeEntity(PreLoadEvent ple, UserAttributeEntity uae) {
        EntityManager em = (EntityManager) ple.getSession();
        Map<String, Integer> cols = collectColumnIndices(ple.getPersister().getEntityMetamodel().getPropertyNames());
        Object[] states = ple.getState();
        String valueColumn;
        if (states[cols.get("value")] != null) {
            valueColumn = "value";
        } else if (states[cols.get("longValue")] != null) {
            valueColumn = "longValue";
        } else {
            return; // null value = do nothing
        }
        UserEntity user = (UserEntity) states[cols.get("user")];
        EncryptedUserAttributeEntity euae = LogicUtils.getEncryptedUserAttributeEntity(em, user, String.valueOf(states[cols.get("name")]), false);
        String userAttributeAad = LogicUtils.attributeAad(user.getId(), euae != null ? euae.getName() : String.valueOf(states[cols.get("name")]));
        if (euae != null) {
            // if record exist, decrypt it and set as value column
            if (validateHashValueVsEncryptedValue((String) states[cols.get(valueColumn)], euae.getValue(), userAttributeAad)) {
                logger.debugf("Event: USER_ATTRIBUTE_DECRYPTION, Realm: %s, User: %s, Attribute: %s", user.getRealmId(), user.getId(), states[cols.get("name")]);
                states[cols.get(valueColumn)] = PiiCipher.getInstance().decryptString(euae.getValue(), userAttributeAad);
            } else {
                throw new DecryptionFailureException(user.getRealmId(), user.getId(), (String) states[cols.get("name")]);
            }
        } else if (PiiCipher.isProtected(String.valueOf(states[cols.get("value")]))) {
            // if the value column is encrypted value (backward compatibility with version 1.x)
            states[cols.get("value")] = PiiCipher.getInstance().decryptString(String.valueOf(states[cols.get("value")]), userAttributeAad);
        }
    }

    private void handlePreInsertUserEntity(PreInsertEvent ple, UserEntity ue) {
        EntityManager em = (EntityManager) ple.getSession();
        Map<String, Integer> cols = collectColumnIndices(ple.getPersister().getEntityMetamodel().getPropertyNames());
        String realmId = (String) ple.getState()[cols.get("realmId")];
        if (realmId == null || !LogicUtils.isUserEncryptionEnabled(em, realmId)) {
            return;
        }
        String username = (String) ple.getState()[cols.get("username")];
        if (username != null && LogicUtils.isHash(username)) {
            // already hashed/encrypted - nothing to do
            return;
        }
        EncryptedUserEntity eue = LogicUtils.getEncryptedUserEntity(em, ue, true);
        PiiCipher cipher = PiiCipher.getInstance();
        String userId = ue.getId();
        eue.setUsername(cipher.encryptString(username, LogicUtils.aad(userId, "username")));

        String email = (String) ple.getState()[cols.get("email")];
        String emailNormalized = email != null ? email.trim() : "";
        if (emailNormalized.isBlank()) {
            emailNormalized = "";
        }
        eue.setEmail(cipher.encryptString(emailNormalized, LogicUtils.aad(userId, "email")));

        String firstName = (String) ple.getState()[cols.get("firstName")];
        String lastName = (String) ple.getState()[cols.get("lastName")];
        firstName = firstName != null ? firstName.trim() : "";
        lastName = lastName != null ? lastName.trim() : "";
        if (firstName.isBlank()) {
            firstName = "";
        }
        if (lastName.isBlank()) {
            lastName = "";
        }
        eue.setFirstName(cipher.encryptString(firstName, LogicUtils.aad(userId, "firstName")));
        eue.setLastName(cipher.encryptString(lastName, LogicUtils.aad(userId, "lastName")));
        em.persist(eue);

        // Update states to blind-index hashes
        ple.getState()[cols.get("username")] = LogicUtils.hash(username);
        String emailHash = emailNormalized.isEmpty() ? null : LogicUtils.hash(emailNormalized);
        ple.getState()[cols.get("email")] = emailHash;

        // Handle emailConstraint - need to check realm's duplicateEmailsAllowed
        RealmEntity realm = em.find(RealmEntity.class, realmId);
        boolean duplicateEmailsAllowed = realm != null && realm.isDuplicateEmailsAllowed();
        if (!duplicateEmailsAllowed) {
            if (emailHash != null) {
                ple.getState()[cols.get("emailConstraint")] = emailHash;
            } else {
                ple.getState()[cols.get("emailConstraint")] = ue.getEmailConstraint();
            }
        }

        ple.getState()[cols.get("firstName")] = LogicUtils.hash(firstName);
        ple.getState()[cols.get("lastName")] = LogicUtils.hash(lastName);
        logger.debugf("Event: USER_ENCRYPTION, Realm: %s, User: %s", realmId, userId);
    }

    private void handlePreUpdateUserEntity(PreUpdateEvent ple, UserEntity ue) {
        EntityManager em = (EntityManager) ple.getSession();
        Map<String, Integer> cols = collectColumnIndices(ple.getPersister().getEntityMetamodel().getPropertyNames());
        String realmId = (String) ple.getState()[cols.get("realmId")];
        if (realmId == null || !LogicUtils.isUserEncryptionEnabled(em, realmId)) {
            return;
        }
        String username = (String) ple.getState()[cols.get("username")];
        if (username != null && LogicUtils.isHash(username)) {
            // already hashed/encrypted - nothing to do
            return;
        }
        EncryptedUserEntity eue = LogicUtils.getEncryptedUserEntity(em, ue, true);
        PiiCipher cipher = PiiCipher.getInstance();
        String userId = ue.getId();
        eue.setUsername(cipher.encryptString(username, LogicUtils.aad(userId, "username")));

        String email = (String) ple.getState()[cols.get("email")];
        String emailNormalized = email != null ? email.trim() : "";
        if (emailNormalized.isBlank()) {
            emailNormalized = "";
        }
        eue.setEmail(cipher.encryptString(emailNormalized, LogicUtils.aad(userId, "email")));

        String firstName = (String) ple.getState()[cols.get("firstName")];
        String lastName = (String) ple.getState()[cols.get("lastName")];
        firstName = firstName != null ? firstName.trim() : "";
        lastName = lastName != null ? lastName.trim() : "";
        if (firstName.isBlank()) {
            firstName = "";
        }
        if (lastName.isBlank()) {
            lastName = "";
        }
        eue.setFirstName(cipher.encryptString(firstName, LogicUtils.aad(userId, "firstName")));
        eue.setLastName(cipher.encryptString(lastName, LogicUtils.aad(userId, "lastName")));
        em.persist(eue);

        // Update states to blind-index hashes
        ple.getState()[cols.get("username")] = LogicUtils.hash(username);
        String emailHash = emailNormalized.isEmpty() ? null : LogicUtils.hash(emailNormalized);
        ple.getState()[cols.get("email")] = emailHash;

        // Handle emailConstraint - need to check realm's duplicateEmailsAllowed
        RealmEntity realm = em.find(RealmEntity.class, realmId);
        boolean duplicateEmailsAllowed = realm != null && realm.isDuplicateEmailsAllowed();
        if (!duplicateEmailsAllowed) {
            if (emailHash != null) {
                ple.getState()[cols.get("emailConstraint")] = emailHash;
            } else {
                ple.getState()[cols.get("emailConstraint")] = ue.getEmailConstraint();
            }
        }

        ple.getState()[cols.get("firstName")] = LogicUtils.hash(firstName);
        ple.getState()[cols.get("lastName")] = LogicUtils.hash(lastName);
        logger.debugf("Event: USER_ENCRYPTION, Realm: %s, User: %s", realmId, userId);
    }

    private void handlePreInsertUserAttributeEntity(PreInsertEvent ple, UserAttributeEntity uae) {
        EntityManager em = (EntityManager) ple.getSession();
        Map<String, Integer> cols = collectColumnIndices(ple.getPersister().getEntityMetamodel().getPropertyNames());
        String valueColumn;
        Object value = ple.getState()[cols.get("value")];
        Object longValue = ple.getState()[cols.get("longValue")];
        if (value != null) {
            valueColumn = "value";
        } else if (longValue != null) {
            valueColumn = "longValue";
        } else {
            return; // null value = do nothing
        }
        UserEntity user = (UserEntity) ple.getState()[cols.get("user")];
        if (!LogicUtils.shouldEncryptAttribute(em, user.getRealmId(), (String) ple.getState()[cols.get("name")])) {
            return;
        }
        String val = String.valueOf(ple.getState()[cols.get(valueColumn)]);
        if (LogicUtils.isHash(val)) {
            return; // already hashed/encrypted
        }
        EncryptedUserAttributeEntity euae = LogicUtils.getEncryptedUserAttributeEntity(em, user, (String) ple.getState()[cols.get("name")], true);
        String encryptedValue = PiiCipher.getInstance().encryptString(val, LogicUtils.attributeAad(user.getId(), euae.getName()));
        euae.setValue(encryptedValue);
        euae.setAttribute(uae);
        em.persist(euae);

        // Generate consistent hashes
        String valueHash = LogicUtils.hash(val);
        byte[] jpHash = JpaHashUtils.hashForAttributeValue(val);
        byte[] jpHashLower = JpaHashUtils.hashForAttributeValueLowerCase(val);

        if (val.length() > 255) {
            ple.getState()[cols.get("value")] = null;
            ple.getState()[cols.get("longValue")] = valueHash;
            ple.getState()[cols.get("longValueHash")] = jpHash;
            ple.getState()[cols.get("longValueHashLowerCase")] = jpHashLower;
        } else {
            ple.getState()[cols.get("value")] = valueHash;
            ple.getState()[cols.get("longValue")] = null;
            ple.getState()[cols.get("longValueHash")] = null;
            ple.getState()[cols.get("longValueHashLowerCase")] = null;
        }
    }

    private void handlePreUpdateUserAttributeEntity(PreUpdateEvent ple, UserAttributeEntity uae) {
        EntityManager em = (EntityManager) ple.getSession();
        Map<String, Integer> cols = collectColumnIndices(ple.getPersister().getEntityMetamodel().getPropertyNames());
        String valueColumn;
        Object value = ple.getState()[cols.get("value")];
        Object longValue = ple.getState()[cols.get("longValue")];
        if (value != null) {
            valueColumn = "value";
        } else if (longValue != null) {
            valueColumn = "longValue";
        } else {
            return; // null value = do nothing
        }
        UserEntity user = (UserEntity) ple.getState()[cols.get("user")];
        if (!LogicUtils.shouldEncryptAttribute(em, user.getRealmId(), (String) ple.getState()[cols.get("name")])) {
            return;
        }
        String val = String.valueOf(ple.getState()[cols.get(valueColumn)]);
        if (LogicUtils.isHash(val)) {
            return; // already hashed/encrypted
        }
        EncryptedUserAttributeEntity euae = LogicUtils.getEncryptedUserAttributeEntity(em, user, (String) ple.getState()[cols.get("name")], true);
        String encryptedValue = PiiCipher.getInstance().encryptString(val, LogicUtils.attributeAad(user.getId(), euae.getName()));
        euae.setValue(encryptedValue);
        euae.setAttribute(uae);
        em.persist(euae);

        // Generate consistent hashes
        String valueHash = LogicUtils.hash(val);
        byte[] jpHash = JpaHashUtils.hashForAttributeValue(val);
        byte[] jpHashLower = JpaHashUtils.hashForAttributeValueLowerCase(val);

        if (val.length() > 255) {
            ple.getState()[cols.get("value")] = null;
            ple.getState()[cols.get("longValue")] = valueHash;
            ple.getState()[cols.get("longValueHash")] = jpHash;
            ple.getState()[cols.get("longValueHashLowerCase")] = jpHashLower;
        } else {
            ple.getState()[cols.get("value")] = valueHash;
            ple.getState()[cols.get("longValue")] = null;
            ple.getState()[cols.get("longValueHash")] = null;
            ple.getState()[cols.get("longValueHashLowerCase")] = null;
        }
    }

    protected static Map<String, Integer> collectColumnIndices(String[] columnNames) {
        Map<String, Integer> cols = new HashMap<>();
        for (int i = 0; i < columnNames.length; i++) {
            cols.put(columnNames[i], i);
        }
        return cols;
    }

    /**
     * Validate if the passed hash value matches with the pass encrypted value
     *
     * @param hash The hash value String
     * @param encryptedValue The encrypted value String
     * @return True if matches, false otherwise
     */
    public static boolean validateHashValueVsEncryptedValue(String hash, String encryptedValue, String aad) {
        return LogicUtils.matchesHash(hash, PiiCipher.getInstance().decryptString(encryptedValue, aad));
    }

    private void handlePreInsertRealmEntity(PreInsertEvent ple, RealmEntity realm) {
        EntityManager em = (EntityManager) ple.getSession();
        String realmId = realm.getId();
        if (realmId == null || !LogicUtils.isSmtpConfigEncryptionEnabled(em, realmId)) {
            return;
        }
        // Get the smtpConfig from the event state
        Object smtpConfigObj = ple.getState()[getPropertyIndex(ple, "smtpConfig")];
        if (smtpConfigObj instanceof Map<?, ?> smtpConfig) {
            for (Map.Entry<?, ?> entry : smtpConfig.entrySet()) {
                String name = String.valueOf(entry.getKey());
                String value = String.valueOf(entry.getValue());
                if (value != null && !value.isEmpty() && !LogicUtils.isHash(value)) {
                    EncryptedRealmSmtpConfigEntity ersce = LogicUtils.getEncryptedRealmSmtpConfigEntity(em, realm, name, true);
                    String encryptedValue = PiiCipher.getInstance().encryptString(value, LogicUtils.smtpAad(realmId, name));
                    ersce.setValue(encryptedValue);
                    em.persist(ersce);
                }
            }
        }
    }

    private void handlePreUpdateRealmEntity(PreUpdateEvent ple, RealmEntity realm) {
        EntityManager em = (EntityManager) ple.getSession();
        String realmId = realm.getId();
        if (realmId == null || !LogicUtils.isSmtpConfigEncryptionEnabled(em, realmId)) {
            return;
        }
        // Get the smtpConfig from the event state
        Object smtpConfigObj = ple.getState()[getPropertyIndex(ple, "smtpConfig")];
        if (smtpConfigObj instanceof Map<?, ?> smtpConfig) {
            for (Map.Entry<?, ?> entry : smtpConfig.entrySet()) {
                String name = String.valueOf(entry.getKey());
                String value = String.valueOf(entry.getValue());
                if (value != null && !value.isEmpty() && !LogicUtils.isHash(value)) {
                    EncryptedRealmSmtpConfigEntity ersce = LogicUtils.getEncryptedRealmSmtpConfigEntity(em, realm, name, true);
                    String encryptedValue = PiiCipher.getInstance().encryptString(value, LogicUtils.smtpAad(realmId, name));
                    ersce.setValue(encryptedValue);
                    em.persist(ersce);
                }
            }
        }
    }

    private int getPropertyIndex(PreInsertEvent ple, String propertyName) {
        String[] propertyNames = ple.getPersister().getEntityMetamodel().getPropertyNames();
        for (int i = 0; i < propertyNames.length; i++) {
            if (propertyNames[i].equals(propertyName)) {
                return i;
            }
        }
        return -1;
    }

    private int getPropertyIndex(PreUpdateEvent ple, String propertyName) {
        String[] propertyNames = ple.getPersister().getEntityMetamodel().getPropertyNames();
        for (int i = 0; i < propertyNames.length; i++) {
            if (propertyNames[i].equals(propertyName)) {
                return i;
            }
        }
        return -1;
    }

}