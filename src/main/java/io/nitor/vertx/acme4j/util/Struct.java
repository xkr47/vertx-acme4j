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
package io.nitor.vertx.acme4j.util;

import java.util.AbstractMap;
import java.util.Map;

import static java.util.stream.Collectors.toMap;

public abstract class Struct implements Cloneable {
    @Override
    public Object clone() {
        try {
            return super.clone();
        } catch (CloneNotSupportedException e) {
            throw new RuntimeException(e);
        }
    }

    protected <K,V extends Struct> Map<K,V> cloneMapValues(Map<K,V> map) {
        return map.entrySet()
                .stream()
                .map(a -> new AbstractMap.SimpleEntry<>(a.getKey(), (V) a.getValue().clone()))
                .collect(toMap(Map.Entry::getKey, Map.Entry::getValue));
    }
}
