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

import java.util.List;
import java.util.stream.Collectors;

import static java.util.stream.Collectors.toList;

public class AcmeConfig extends Struct {
    public List<Account> accounts;

    public void validate() {
        if (accounts == null) throw new NullPointerException();
        accounts.stream().forEach(Account::validate);
    }

    public static class Account extends Struct {
        public String id;
        public String providerUrl;
        public String acceptedAgreementUrl;
        public List<Certificate> certificates;



        @Override
        public Account clone() {
            Account c = (Account) super.clone();
            c.certificates = certificates.stream().map(a -> (Certificate)a.clone()).collect(toList());
            return c;
        }
    }

    public static class Certificate extends Struct {
        public String id;
        public String organization;
        public List<String> hostnames;
    }

    @Override
    public AcmeConfig clone() {
        AcmeConfig c = (AcmeConfig) super.clone();
        c.accounts = accounts.stream().map(a -> (Account)a.clone()).collect(toList());
        return c;
    }
}
