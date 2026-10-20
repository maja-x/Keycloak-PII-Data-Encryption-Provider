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
package my.unifi.eset.keycloak.piidataencryption.jpa;

import jakarta.persistence.EntityManager;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import my.unifi.eset.keycloak.piidataencryption.crypto.PiiCipher;
import my.unifi.eset.keycloak.piidataencryption.crypto.PiiKind;
import my.unifi.eset.keycloak.piidataencryption.utils.LogicUtils;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.jpa.JpaUserProvider;

public class EncryptedUserProvider extends JpaUserProvider {

    private static final Logger logger = Logger.getLogger(EncryptedUserProvider.class);
    private static final List<String> ENCRYPTED_USER_FIELDS = List.of(UserModel.SEARCH, "username", "email", "firstName", "lastName");

    private final KeycloakSession ks;

    public EncryptedUserProvider(KeycloakSession session, EntityManager em) {
        super(session, em);
        this.ks = session;
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        UserModel user = super.getUserByUsername(realm, username);
        if (user != null) {
            return user;
        }
        logger.debugf("getUserByUsername (using blind index): %s", username);
        for (String candidate : hashCandidates(username, PiiKind.GENERIC)) {
            if (null != (user = super.getUserByUsername(realm, candidate))) {
                return user;
            }
        }
        return null;
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        UserModel user = super.getUserByEmail(realm, email);
        if (user != null) {
            return user;
        }
        logger.debugf("getUserByEmail (using blind index): %s", email);
        for (String candidate : hashCandidates(email, PiiKind.EMAIL)) {
            if (null != (user = super.getUserByEmail(realm, candidate))) {
                return user;
            }
        }
        return null;
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, Map<String, String> attributes, Integer firstResult, Integer maxResults) {
        List<UserModel> results = super.searchForUserStream(realm, attributes, firstResult, maxResults).toList();
        if (!results.isEmpty()) {
            return results.stream();
        }
        for (Map<String, String> hashedAttributes : blindIndexedAttributes(realm, attributes)) {
            logger.debugf("searchForUserStream (using blind index): %s", hashedAttributes);
            results = super.searchForUserStream(realm, hashedAttributes, firstResult, maxResults).toList();
            if (!results.isEmpty()) {
                return results.stream();
            }
        }
        return Stream.empty();
    }

    @Override
    public UserModel addUser(RealmModel realm, String id, String username, boolean addDefaultRoles, boolean addDefaultRequiredActions) {
        UserModel userModel = super.addUser(realm, id, username, addDefaultRoles, addDefaultRequiredActions);
        LogicUtils.encryptUserEntity(ks, em, LogicUtils.getUserEntity(em, userModel.getId()));
        em.flush();
        logger.debugf("addUser (encrypted): " + username);
        return userModel;
    }

    /**
     * Computes every hash a value may have in the database: one per configured
     * pepper plus the SHA-1 hash used by version 1.x. This keeps rows that have
     * not been re-indexed after a pepper rotation findable.
     *
     * @param value The plain text value
     * @param kind The kind of value, used for canonicalization
     * @return The candidate hashes, the active one first
     */
    private static List<String> hashCandidates(String value, PiiKind kind) {
        List<String> candidates = PiiCipher.getInstance().searchAll(value, kind);
        List<String> distinct = new ArrayList<>(candidates.size());
        for (String candidate : candidates) {
            if (candidate != null && !distinct.contains(candidate)) {
                distinct.add(candidate);
            }
        }
        return distinct;
    }

    /**
     * Builds the attribute filters for each candidate hash position. The first
     * map hashes every encrypted attribute with the active pepper, the second
     * with the previous pepper (if any), and the last with the legacy SHA-1, so
     * a lookup that misses the active hash can still find old rows.
     *
     * @param realm The realm
     * @param attributes The plain text filters
     * @return The hashed filters, ordered by preference
     */
    private List<Map<String, String>> blindIndexedAttributes(RealmModel realm, Map<String, String> attributes) {
        Map<String, List<String>> candidatesByAttribute = new HashMap<>();
        int positions = 0;
        for (Map.Entry<String, String> attribute : attributes.entrySet()) {
            if (attribute.getValue() == null || !isEncryptedAttribute(realm, attribute.getKey())) {
                continue;
            }
            List<String> candidates = PiiCipher.getInstance().searchAll(attribute.getValue(), kindOf(attribute.getKey()));
            candidatesByAttribute.put(attribute.getKey(), candidates);
            positions = Math.max(positions, candidates.size());
        }
        List<Map<String, String>> hashedAttributes = new ArrayList<>(positions);
        for (int position = 0; position < positions; position++) {
            Map<String, String> hashed = new HashMap<>(attributes);
            for (Map.Entry<String, List<String>> candidate : candidatesByAttribute.entrySet()) {
                List<String> values = candidate.getValue();
                if (!values.isEmpty()) {
                    hashed.put(candidate.getKey(), values.get(Math.min(position, values.size() - 1)));
                }
            }
            hashedAttributes.add(hashed);
        }
        return hashedAttributes;
    }

    private boolean isEncryptedAttribute(RealmModel realm, String attributeName) {
        return ENCRYPTED_USER_FIELDS.contains(attributeName)
                || LogicUtils.shouldEncryptAttribute(ks, realm.getId(), attributeName);
    }

    private static PiiKind kindOf(String attributeName) {
        return "email".equalsIgnoreCase(attributeName) ? PiiKind.EMAIL : PiiKind.GENERIC;
    }

}
