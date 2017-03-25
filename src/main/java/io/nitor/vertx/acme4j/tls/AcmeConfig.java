/*
 * Copyright 2017 Jonas Berlin
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.nitor.vertx.acme4j.tls;

import java.util.AbstractMap;
import java.util.AbstractMap.SimpleEntry;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toMap;

public class AcmeConfig extends Struct {
    public Map<String,Account> accounts;

    public void validate() {
        if (accounts == null) throw new NullPointerException();
        accounts.values().stream().forEach(Account::validate);
    }

    public static class Account extends Struct {
        public String id;
        public String providerUrl;
        public String acceptedAgreementUrl;
        public Map<String, Certificate> certificates;

        public void validate() {
        }

        @Override
        public Account clone() {
            Account c = (Account) super.clone();
            c.certificates = cloneMapValues(certificates);
            return c;
        }
    }

    public static class Certificate extends Struct {
        public String id;
        public String organization;
        public List<String> hostnames;

        @Override
        public Certificate clone() {
            return (Certificate) super.clone();
        }
    }

    @Override
    public AcmeConfig clone() {
        AcmeConfig c = (AcmeConfig) super.clone();
        c.accounts = cloneMapValues(accounts);
        return c;
    }
}
