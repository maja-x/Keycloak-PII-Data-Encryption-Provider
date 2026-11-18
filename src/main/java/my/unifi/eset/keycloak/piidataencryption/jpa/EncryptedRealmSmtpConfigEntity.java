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

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import org.keycloak.models.jpa.entities.RealmEntity;

@Entity
@Table(name = "REALM_SMTP_CONFIG_ENCRYPTED")
public class EncryptedRealmSmtpConfigEntity {

    @Id
    @Column(name = "ID", length = 36)
    protected String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "REALM_ID")
    protected RealmEntity realm;

    @Column(name = "NAME", length = 255)
    protected String name;

    @Column(name = "VALUE")
    protected String value;

    public EncryptedRealmSmtpConfigEntity() {
    }

    public EncryptedRealmSmtpConfigEntity(String id, RealmEntity realm, String name) {
        this.id = id;
        this.realm = realm;
        this.name = name;
    }

    public String getId() {
        return id;
    }

    public RealmEntity getRealm() {
        return realm;
    }

    public String getName() {
        return name;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

}